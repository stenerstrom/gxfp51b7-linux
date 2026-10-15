"""One finite paired original-Engine worker, with no image API to libfprint.

The privileged parent owns sensor transport and encrypted BIOS input. A child
with permanently dropped privileges owns LE/WBDI/Engine and original action
state. A separate control socket permits frame retries without process restarts.
"""
import errno
import json
import os
from pathlib import Path
import select
import socket
import sys
import time

import engine_v2_protocol as wire
from persistent_reader import session_log, SESSION_LOG_LIMIT
from fprint_backend import WORKER_STATUS_FIELDS, numeric_status_line
from run_trial import drop_privileges, reap_worker
from sealed_input import create_sealed_input
from service_reader import restored
from transport_server import serve_transport_once

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BUILD = HERE / 'engine-service-build'
INTEL = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
ORIGINAL = PROJECT / 'windows-driver-1.1.151.18/extracted/source'
STARTUP_SECONDS = 120
STEP_SECONDS = 60
CLOSE_SECONDS = 45
SESSION_SECONDS = 1200
MAX_RPC_REQUESTS = 65536
MAX_FRAMES = 512
ENGINE_STATUS_FIELDS = WORKER_STATUS_FIELDS | frozenset('''
application_calls application_result base_valid_output baseline_export_sgx_result
baseline_image_exit_result baseline_quality_sgx_result baseline_queue_sgx_result
baseline_sensor_identity_result baseline_tls_init_sgx_result baseline_transport_finish_result
baseline_unexpected_engine_callback baseline_update_sgx_result bios calibration_failed
calibration_reads calibration_writes dh_ecall discarded_adaptive_update einit_attempted
einit_result empty engine_attach_sgx_result engine_baseline_attach_sgx_result
engine_baseline_detach_sgx_result engine_baseline_init_sgx_result engine_baseline_mode_sgx_result
engine_baseline_overlay_sgx_result engine_baseline_profile engine_detach_sgx_result
engine_einit_result engine_log_callbacks_discarded engine_logs_discarded engine_overlay_sgx_result
engine_probe_result engine_profile engine_runtime_init_result engine_unsupported_or_invalid_ocall
engine_call_cancelled_or_ocall_limit engine_ecall_number wbdi_ecall_number exact_length expected
frames initialized intel_le_runtime_result key_length_valid original_baseline_probe_result
original_engine_service_result output_length pair_le_einit_result pair_le_token_sgx_result
pair_le_whitelist_sgx_result pair_probe_result pair_side plaintext_length reader retries
runtime_attempted runtime_result save_base state_ecall template tls_exit_result
unexpected_or_invalid_ocall value version_matches_original wbdi_logs_discarded
service_action_stage service_sgx_status service_application_result service_original_classifier
service_retry_worker_retained
'''.split())


def engine_status_and_close(fd):
    """Retain bounded numeric stage records, then erase and close the RAM log."""
    data = bytearray(SESSION_LOG_LIMIT)
    status, records = {}, []
    try:
        if os.fstat(fd).st_size != SESSION_LOG_LIMIT:
            raise ValueError('Invalid original Engine RAM log size')
        count = os.preadv(fd, [data], 0)
        position = 0
        while position < count:
            end = data.find(b'\n', position, count)
            if end < 0:
                end = count
            if 0 < end - position <= 256:
                line = data[position:end]
                try:
                    record = numeric_status_line(line, ENGINE_STATUS_FIELDS)
                    if record:
                        status.update(record)
                        records.append(record)
                        if len(records) > 128:
                            records.pop(0)
                finally:
                    wire.erase(line)
            position = end + 1
        return status, records
    finally:
        wire.erase(data)
        try:
            position = 0
            while position < len(data):
                written = os.pwrite(fd, memoryview(data)[position:], position)
                if written <= 0:
                    raise OSError('Original Engine RAM log erasure failed')
                position += written
        finally:
            os.close(fd)


class UnreapedWorker(BaseException):
    """Fatal service condition: its supervisor must finish cgroup cleanup.

    This deliberately bypasses per-request Exception handling. Continuing to
    accept claims with an unaccounted child could create competing readers.
    """


def runner_arguments(epc_fd, sealed_fd, transport_fd, command_fd):
    if any(type(fd) is not int or fd < 0 for fd in
           (epc_fd, sealed_fd, transport_fd, command_fd)):
        raise ValueError('The original Engine worker requires four inherited descriptors')
    return [str(BUILD / 'engine_service_runner'), str(epc_fd), str(BUILD / 'intel-le.plan'),
            str(INTEL / 'le_prod_css.bin'), str(BUILD / 'wbdi.plan'),
            str(BUILD / 'engine.plan'), str(ORIGINAL / 'sgx_white_list_cert.bin'),
            str(sealed_fd), str(transport_fd), str(command_fd)]


def default_bridge(report):
    sys.path.insert(0, str(PROJECT / 'sgx-vm'))
    from tls_bridge import TlsBridge
    return TlsBridge(report, allow_capture=True, original_engine_session=True)


class EngineReader:
    """Private worker session. Public ownership and IDs belong to the backend."""
    def __init__(self, report=None, bridge_factory=default_bridge):
        self.report = report or (lambda message: print(message, flush=True))
        self.bridge_factory = bridge_factory
        self.frames = 0
        self.bridge = self.transport = self.control = None
        self.transport_child = self.control_child = None
        self.epc_fd = self.sealed_fd = self.log_fd = -1
        self.pid = -1
        self.session_id = self.sequence = self.requests = 0
        self.started = time.monotonic()
        self.closed = False
        self.last_exit_code = None
        self.last_factory_status = {}
        self.last_worker_status = {}
        self.last_worker_records = []
        self.transport_finished = False
        self.cancelled_after_reply = False

    def start(self):
        if self.closed or self.pid > 0 or self.control is not None:
            raise RuntimeError('Original Engine worker already started or closed')
        try:
            self.sealed_fd = create_sealed_input(report=self.report)
            self.epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
            self.log_fd = session_log()
            self.bridge = self.bridge_factory(self.report)
            self.transport, self.transport_child = socket.socketpair()
            self.control, self.control_child = socket.socketpair()
            inherited = (self.epc_fd, self.sealed_fd,
                         self.transport_child.fileno(), self.control_child.fileno())
            for fd in inherited:
                os.set_inheritable(fd, True)
            args = runner_arguments(*inherited)
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    self.transport.close()
                    self.control.close()
                    os.dup2(self.log_fd, 1)
                    os.dup2(self.log_fd, 2)
                    drop_privileges()
                    os.execve(args[0], args, {'PATH': '/usr/bin'})
                except BaseException:
                    os._exit(1)
            for name in ('transport_child', 'control_child'):
                getattr(self, name).close()
                setattr(self, name, None)
            for name in ('epc_fd', 'sealed_fd'):
                os.close(getattr(self, name))
                setattr(self, name, -1)
        except BaseException as error:
            self._fail(error)

    def _exchange(self, operation, payload=None, cancelled=lambda: False):
        if self.closed or self.control is None:
            raise OSError(errno.ENOTCONN, 'Original Engine worker is not connected')
        self.sequence += 1
        if self.sequence >= 2**32:
            raise RuntimeError('Original Engine sequence exhausted')
        timeout = STARTUP_SECONDS if operation == wire.OPEN_SESSION else (
            CLOSE_SECONDS if operation in (wire.END_ACTION, wire.CLOSE_SESSION) else STEP_SECONDS)
        deadline = min(self.started + SESSION_SECONDS, time.monotonic() + timeout)
        if deadline <= time.monotonic():
            raise TimeoutError('Original Engine session lifetime expired')
        cancellation_seen = cancelled()
        self.cancelled_after_reply = False
        request = wire.Request(operation, self.sequence,
                               0 if operation == wire.OPEN_SESSION else self.session_id,
                               payload if payload is not None else bytearray())
        self.control.settimeout(min(5, deadline - time.monotonic()))
        wire.send_request(self.control, request)
        while True:
            # A cancelled public socket must not cut off the sensor RPC needed
            # to finish this one bounded call and close the original session.
            # No subsequent STEP is sent; malformed transport still fails fast.
            cancellation_seen = cancellation_seen or cancelled()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Original Engine operation deadline')
            channels = [self.control] if self.transport_finished else [self.control, self.transport]
            ready, _, _ = select.select(channels, [], [], min(remaining, .1))
            # Service transport first when both are ready: close acknowledgements
            # are not forwarded while a final sensor restoration RPC is pending.
            if self.transport in ready:
                if self.requests >= MAX_RPC_REQUESTS:
                    raise RuntimeError('Original Engine transport request limit')
                sensor_operation, status = serve_transport_once(
                    self.transport, self.bridge, min(remaining, 60),
                    allow_capture=True, allow_session=True, allow_engine_metadata=True)
                self.requests += 1
                if sensor_operation == 7 and status == 0:
                    self.frames += 1
                    if self.frames > MAX_FRAMES:
                        raise RuntimeError('Original Engine source frame limit')
                if sensor_operation == 5:
                    self.transport_finished = True
                    if status:
                        raise OSError(errno.EIO, 'Original Engine transport close failed')
            if self.control in ready:
                self.control.settimeout(max(.001, min(5, deadline - time.monotonic())))
                reply = wire.read_reply(self.control, request)
                if self.transport_finished and not reply.status and operation not in (
                        wire.END_ACTION, wire.CLOSE_SESSION):
                    reply.close()
                    raise OSError(errno.EIO, 'Original Engine success followed an unexpected transport end')
                if operation == wire.OPEN_SESSION and not reply.status:
                    self.session_id = reply.session_id
                self.cancelled_after_reply = cancellation_seen or cancelled()
                return reply

    def request(self, operation, payload=None, cancelled=lambda: False):
        """Send one action command; a failed exchange destroys uncertain state."""
        if cancelled():
            error = OSError(errno.ECANCELED, 'Original Engine client disconnected')
            try:
                self.close(graceful=True)
            except BaseException as cleanup:
                raise BaseExceptionGroup('Original Engine cancellation and cleanup failed',
                                          [error, cleanup]) from None
            raise error
        if operation == wire.OPEN_SESSION and self.pid < 0 and not self.closed:
            self.start()
        try:
            reply = self._exchange(operation, payload, cancelled)
            was_cancelled = self.cancelled_after_reply
            if reply.status:
                error = OSError(reply.status, 'Original Engine worker operation failed')
                reply.close()
                raise error
            retained = bool(reply.flags & wire.RETRY_SESSION_RETAINED)
            if retained and (operation != wire.END_ACTION or self.transport_finished or
                             self.closed or self.pid <= 0 or self.control is None):
                reply.close()
                raise OSError(errno.EPROTO, 'Retained retry has no healthy worker transport')
            if operation in (wire.END_ACTION, wire.CLOSE_SESSION) and not retained:
                try:
                    self.close(graceful=False)
                except BaseException:
                    reply.close()
                    raise
            if was_cancelled:
                reply.close()
                self.close(graceful=True)
                raise OSError(errno.ECANCELED, 'Original Engine client disconnected')
            return reply
        except BaseException as error:
            self._fail(error)

    def _fail(self, error):
        try:
            self.close(graceful=False)
        except BaseException as cleanup:
            raise BaseExceptionGroup('Original Engine operation and cleanup failed',
                                      [error, cleanup]) from None
        raise error

    def close(self, graceful=True):
        if self.closed:
            if self.last_exit_code:
                raise OSError(errno.EIO, 'Original Engine worker cleanup previously failed')
            return self.last_exit_code or 0
        failures = []
        result = 0 if self.pid < 0 else -1
        if graceful and self.control is not None and self.session_id:
            try:
                reply = self._exchange(wire.CLOSE_SESSION)
                try:
                    if reply.status or reply.event != wire.CLOSED:
                        raise OSError(errno.EIO, 'Original Engine close was not acknowledged')
                finally:
                    reply.close()
            except BaseException as error:
                failures.append(error)
        self.closed = True
        for name in ('control', 'transport', 'control_child', 'transport_child'):
            connection = getattr(self, name)
            setattr(self, name, None)
            if connection is not None:
                try:
                    connection.close()
                except BaseException as error:
                    failures.append(error)
        if self.pid > 0:
            try:
                try:
                    result = reap_worker(self.pid, time.monotonic() + 35)
                except BaseException as error:
                    raise UnreapedWorker('Original Engine child could not be reaped') from error
                self.pid = -1
                if result:
                    raise OSError(errno.EIO, 'Original Engine worker exited unsuccessfully')
            except BaseException as error:
                failures.append(error)
        if self.bridge is not None:
            bridge, self.bridge = self.bridge, None
            try:
                bridge.close()
            except BaseException as error:
                failures.append(error)
            finally:
                self.last_factory_status = dict(getattr(bridge, 'factory_status', {}))
            if not restored(self.last_factory_status):
                failures.append(OSError(errno.EIO, 'Original Engine factory restoration was not verified'))
        for name in ('log_fd', 'epc_fd', 'sealed_fd'):
            fd = getattr(self, name)
            setattr(self, name, -1)
            if fd >= 0:
                try:
                    if name == 'log_fd':
                        self.last_worker_status, self.last_worker_records = engine_status_and_close(fd)
                    else:
                        os.close(fd)
                except BaseException as error:
                    failures.append(error)
        self.last_exit_code = result if not failures else result or 1
        self.report('engine_worker_closed=1 exit=' + str(self.last_exit_code) +
                    ' frames=' + str(self.frames) +
                    ' restored=' + str(int(restored(self.last_factory_status))))
        if self.last_worker_records:
            self.report('engine_worker_diagnostics=' + json.dumps(self.last_worker_records,
                                                                 separators=(',', ':')))
        if failures:
            if len(failures) == 1:
                raise failures[0]
            raise BaseExceptionGroup('Original Engine cleanup failed', failures)
        return result
