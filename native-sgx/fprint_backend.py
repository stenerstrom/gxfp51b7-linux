#!/usr/bin/env python3
"""Development backend for the physical GXFP51B7 libfprint image driver.

Start once with local pkexec authentication and the sensor empty. The initial
authenticated frame is the RAM-only background. Each libfprint operation uses
one bounded factory-calibrated SGX/TLS session, restored at END/cancellation.
Only root peers (the ordinary fprintd daemon) may request images. No PAM change
or system installation is performed. This Work checkout is not a trusted
production root installation.
"""
from array import array
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import resource
import re
import select
import signal
import socket
import stat
import sys
import time

from fprint_protocol import DESCRIBE, CAPTURE, BACKGROUND, read_operation, root_peer, send_reply, send_error
from fprint_protocol import error_metadata as request_error_metadata
from run_trial import run_tls_trial
from sealed_input import create_sealed_input

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
DEFAULT_SOCKET = PROJECT / 'linux-driver/native-runtime/reader.sock'
WORKER_LOG_LIMIT = 65536
WORKER_STATUS_FIELDS = frozenset('''
intel_le_einit_result intel_le_einit_retries intel_le_runtime_init_result intel_le_whitelist_sgx_result whitelist_result
intel_le_token_sgx_result token_request_result goodix_einit_result goodix_einit_retries goodix_runtime_init_result
goodix_application_init_result goodix_tls_init_result tls_bridge_start_result tls_read_result tls_state
tls_connected_callbacks invalid_mac_callbacks sensor_connected_flag tls_rx_ocalls tls_tx_ocalls
bridge_crc_ok bridge_crc_bad image_init_result goodix_result image_size imagebase_size
native_capture_request_result native_capture_read_result native_image_authenticated_plaintext_bytes
native_source_export_result image_crc_valid image_ready_callbacks native_capture_host_result
source_packet_erased raw_image_logged tls_bridge_finish_result goodix_tls_exit_result
filtered_log_ocalls pmk_success_length unseal_error me_info_ocalls cache_miss_ocalls
tls_final_connected_callbacks trial_result goodix_einit_attempted bios_read tls_sensor_connected
unexpected_kvm_exit untrusted_stack_out_of_bounds unsupported_ocall_index ocall_limit_reached
ecall_number return_call sgx_result asynchronous_exits goodix_ecall_number ocalls
vm_closed epc_mapping_released
'''.split())
STATUS_TOKEN = re.compile(rb'([a-z_]+)=(-?[0-9]{1,10}|0x[0-9a-f]{1,8})\Z')
TRANSPORT_PREFIXES = ('stream_control_wait_command=', 'stream_control_ack_command=',
                      'stream_original_default_config_error=', 'stream_image_request_error=',
                      'stream_config_response_received=', 'stream_capture_idle_error=',
                      'stream_start_error=', 'stream_negotiation_finish_error=',
                      'stream_final_state_error=', 'stream_unloaded_error=',
                      'stream_after_unload_state_error=', 'factory_transfer_command=',
                      'factory_read_retry_command=', 'factory_wait_command=', 'factory_irq_ack_command=',
                      'factory_ready_command=')
TRANSPORT_FIELDS = frozenset('''
stream_control_wait_command stream_control_ack_command stream_original_default_config_error
stream_image_request_error stream_config_response_received stream_capture_idle_error
stream_start_error stream_negotiation_finish_error stream_final_state_error
stream_unloaded_error stream_after_unload_state_error error ack_status config_response
status sensor_type payload_bytes otp_patches command buffered_tls_bytes tls_connected
factory_transfer_command factory_transfer_error factory_transfer_frames factory_transfer_ack factory_transfer_response
factory_read_retry_command factory_read_retry_error factory_read_retry_attempts
factory_wait_command polls irq_delta gpio_start gpio_end changed_polls falling_edges invalid_frames unstable_frames
factory_irq_ack_command used
factory_ready_command ready ready_wait_polls submitted
'''.split())


def numeric_status_line(line, allowed):
    if not 0 < len(line) <= 256:
        return {}
    values = {}
    for token in line.split():
        match = STATUS_TOKEN.fullmatch(token)
        if match is None:
            return {}
        name = match[1].decode('ascii')
        if name not in allowed:
            return {}
        value = match[2]
        values[name] = int(value, 16 if value.startswith(b'0x') else 10)
    return values


def transport_status(message):
    records = []
    for line in message[:65536].splitlines():
        if line.startswith(TRANSPORT_PREFIXES):
            try:
                record = numeric_status_line(line.encode('ascii'), TRANSPORT_FIELDS)
            except UnicodeEncodeError:
                continue
            if record:
                records.append(record)
    return records[-64:]


def worker_log():
    """Bounded anonymous RAM log; the child cannot enlarge it."""
    fd = os.memfd_create('gxfp51b7-worker-status', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd, WORKER_LOG_LIMIT)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        return fd
    except BaseException:
        os.close(fd)
        raise


def worker_status(fd):
    """Only allowlisted numeric fields may leave the anonymous worker log."""
    data = bytearray(WORKER_LOG_LIMIT)
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        count = os.readv(fd, [data])
        latest = {}
        for line in memoryview(data)[:count].tobytes().splitlines():
            latest.update(numeric_status_line(line, WORKER_STATUS_FIELDS))
        return latest
    finally:
        data[:] = b'\0' * len(data)


def close_worker_log(fd):
    position = 0
    zeros = b'\0' * WORKER_LOG_LIMIT
    try:
        while position < WORKER_LOG_LIMIT:
            position += os.pwrite(fd, zeros[position:], position)
    finally:
        os.close(fd)


def preimage_negotiation_failure(status):
    """The observed TLS state-8 failure, with no image or integrity failure.

    -0x7080 is mbedTLS FEATURE_UNAVAILABLE, not a bad-MAC or timeout code.
    Only this complete status profile may ask libfprint for a fresh session.
    No cipher setting, key handling, TLS verification or CRC check is changed.
    """
    zero_fields = ('intel_le_einit_result', 'goodix_einit_result', 'goodix_runtime_init_result',
                   'goodix_application_init_result', 'goodix_tls_init_result', 'tls_bridge_start_result',
                   'sgx_result', 'unseal_error', 'tls_final_connected_callbacks',
                   'invalid_mac_callbacks', 'tls_sensor_connected')
    return (all(status.get(field) == 0 for field in zero_fields) and
            status.get('tls_read_result') == -0x7080 and status.get('tls_state') == 8 and
            status.get('pmk_success_length') == 48 and status.get('trial_result') == -1 and
            status.get('vm_closed') == 1 and status.get('epc_mapping_released') == 1 and
            'native_capture_request_result' not in status and
            status.get('native_image_authenticated_plaintext_bytes', 0) == 0 and
            status.get('bridge_crc_bad', 0) == 0 and status.get('image_crc_valid', 0) == 0)


def peer_disconnected(connection):
    """Check EOF without consuming bytes or blocking a capture retry."""
    poll = select.poll()
    poll.register(connection, select.POLLIN | select.POLLHUP | select.POLLERR)
    events = poll.poll(0)
    if any(flags & (select.POLLHUP | select.POLLERR | select.POLLNVAL) for _, flags in events):
        return True
    if any(flags & select.POLLIN for _, flags in events):
        try:
            return not connection.recv(1, socket.MSG_PEEK | socket.MSG_DONTWAIT)
        except BlockingIOError:
            return False
        except OSError:
            return True
    return False


def erase(pixels):
    if pixels is not None:
        for index in range(len(pixels)):
            pixels[index] = 0


class NativeReader:
    def __init__(self, verbose=False):
        self.sealed_fd = create_sealed_input()
        os.set_inheritable(self.sealed_fd, False)
        self.background = None
        self.count = 0
        self.verbose = verbose

    def capture(self, cancelled=None):
        # Only the observed pre-image control timeout is retried. Every
        # attempt still completes fresh SGX/TLS/CRC checks and full cleanup.
        for attempt in range(3):
            if cancelled is not None and cancelled():
                raise OSError(errno.ECANCELED, 'Native capture client disconnected')
            try:
                return self._capture_once()
            except OSError as error:
                if error.errno != errno.ETIMEDOUT or attempt == 2:
                    raise
                print('libfprint_native_capture_retry=' + str(attempt + 1) +
                      ' reason=control_timeout authenticated_image_returned=0', flush=True)

    def _capture_once(self):
        pixels = None
        result = None
        controls = []
        epc_fd = sealed_fd = log_fd = -1

        def receive_image(decoded):
            nonlocal pixels
            if pixels is not None or len(decoded) != 5120:
                raise RuntimeError('Unexpected native image callback')
            pixels = array('H', decoded)

        def report(message):
            if self.verbose or message.startswith(('native_sgx_worker_exit=', 'native_sgx_operation_error=')):
                print(message, flush=True)
            else:
                controls.extend(transport_status(message))
                del controls[:-64]

        started = time.monotonic()
        try:
            epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
            os.set_inheritable(epc_fd, True)
            os.lseek(self.sealed_fd, 0, os.SEEK_SET)
            sealed_fd = os.dup(self.sealed_fd)
            os.set_inheritable(sealed_fd, True)
            if not self.verbose:
                log_fd = worker_log()
            # run_tls_trial assumes ownership of both input FDs on every path.
            owned_epc, owned_sealed = epc_fd, sealed_fd
            epc_fd = sealed_fd = -1
            result = run_tls_trial(owned_epc, owned_sealed, capture=True,
                                   image_consumer=receive_image, report=report,
                                   worker_log_fd=log_fd if log_fd >= 0 else None)
            if result or pixels is None:
                if log_fd >= 0:
                    status = worker_status(log_fd)
                    if status.get('native_capture_request_result') == errno.ETIMEDOUT:
                        raise OSError(errno.ETIMEDOUT, 'Native pre-image control timeout')
                    if pixels is None and preimage_negotiation_failure(status):
                        raise OSError(errno.EAGAIN, 'Native pre-image TLS negotiation failed')
                raise OSError(errno.EIO, 'Native authenticated image capture failed')
            self.count += 1
            print('libfprint_native_frame=' + str(self.count) + ' authenticated=1 crc_valid=1 elapsed=' +
                  format(time.monotonic() - started, '.2f') + ' image_bytes_logged=0', flush=True)
            output, pixels = pixels, None
            return output
        finally:
            erase(pixels)
            try:
                if result != 0 and controls:
                    print('libfprint_native_transport_status=' +
                          json.dumps(controls, separators=(',', ':')), flush=True)
                if log_fd >= 0:
                    try:
                        status = worker_status(log_fd)
                        if (result != 0 or status.get('intel_le_einit_retries', 0) or
                                status.get('goodix_einit_retries', 0)):
                            print('libfprint_native_worker_status=' +
                                  json.dumps(status, separators=(',', ':')), flush=True)
                    finally:
                        close_worker_log(log_fd)
            finally:
                for fd in (epc_fd, sealed_fd):
                    if fd >= 0:
                        os.close(fd)

    def calibrate(self):
        erase(self.background)
        self.background = self.capture()
        print('libfprint_native_background_ready=1 ram_only=1', flush=True)

    def serve_one(self, connection):
        # Check the real peer before reading a request or touching hardware.
        if not root_peer(connection):
            print('libfprint_backend_nonroot_peer_rejected=1', flush=True)
            return
        connection.settimeout(45)
        pixels = None
        try:
            operation = read_operation(connection)
            if operation == DESCRIBE:
                send_reply(connection)
            elif operation == BACKGROUND:
                send_reply(connection, pixels=self.background)
            elif operation == CAPTURE:
                pixels = self.capture(cancelled=lambda: peer_disconnected(connection))
                send_reply(connection, pixels=pixels)
        except (EOFError, ValueError, OSError) as error:
            print(request_error_metadata(error), flush=True)
            try:
                send_error(connection, error)
            except OSError:
                pass
        finally:
            erase(pixels)

    def close(self):
        erase(self.background)
        self.background = None
        if self.sealed_fd >= 0:
            os.close(self.sealed_fd)
            self.sealed_fd = -1
        print('libfprint_backend_ram_erased=1', flush=True)


def check_machine():
    if os.geteuid() != 0 or not (os.environ.get('PKEXEC_UID') == '1000' or
                               os.environ.get('GXFP51B7_SERVICE') == '1'):
        raise RuntimeError('Start the development backend through pkexec as the UID1000 desktop owner')
    for name, expected in (('sys_vendor', 'HUAWEI'), ('product_name', 'MACHC-WAX9')):
        if Path('/sys/class/dmi/id', name).read_text().strip() != expected:
            raise RuntimeError('Unexpected computer')
    alias = Path('/sys/bus/platform/devices/GXFP51B7:00/modalias').read_text().strip()
    if alias != 'acpi:GXFP51B7:GXFP51B7:':
        raise RuntimeError('Unexpected fingerprint device')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def listen(reader, socket_path, lifetime=1800, ready_callback=None):
    directory = socket_path.parent
    created_directory = False
    bound = False
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        if not directory.exists():
            directory.mkdir(mode=0o700)
            created_directory = True
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise RuntimeError('Backend runtime directory must be root-owned with mode 0700')
        if socket_path.exists() or socket_path.is_symlink():
            raise RuntimeError('Backend socket already exists')
        listener.bind(str(socket_path))
        bound = True
        os.chmod(socket_path, 0o600)
        listener.listen(4)
        listener.settimeout(1)
        print('libfprint_native_backend_ready=1 socket=' + str(socket_path), flush=True)
        notify_path = os.environ.get('NOTIFY_SOCKET')
        if notify_path:
            if notify_path.startswith('@'):
                notify_path = '\0' + notify_path[1:]
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as notifier:
                notifier.sendto(b'READY=1', notify_path)
        if ready_callback is not None:
            ready_callback()
        deadline = time.monotonic() + lifetime if lifetime else None
        while deadline is None or time.monotonic() < deadline:
            try:
                connection, address = listener.accept()
            except socket.timeout:
                if hasattr(reader, 'idle_cleanup'):
                    try:
                        reader.idle_cleanup()
                    except Exception as error:
                        # Keep the failed close in this reader instance until
                        # its authenticated owner receives an explicit END.
                        print(request_error_metadata(error), flush=True)
                continue
            with connection:
                reader.serve_one(connection)
    finally:
        listener.close()
        if bound:
            socket_path.unlink(missing_ok=True)
        if created_directory:
            directory.rmdir()


def stop(signum, frame):
    raise KeyboardInterrupt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', type=Path, default=DEFAULT_SOCKET)
    parser.add_argument('--lifetime', type=int, default=1800)
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if not 0 <= args.lifetime <= 3600 or not args.socket.is_absolute():
        parser.error('Use an absolute socket path and a lifetime of 0..3600 seconds (0: service)')
    check_machine()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    from service_reader import PersistentServiceReader
    reader = PersistentServiceReader(args.verbose)
    try:
        reader.calibrate()
        listen(reader, args.socket, args.lifetime)
    except KeyboardInterrupt:
        pass
    finally:
        reader.close()


if __name__ == '__main__':
    main()
