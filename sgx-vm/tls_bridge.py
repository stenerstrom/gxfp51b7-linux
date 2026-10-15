"""Root-only adapter for TLS and an optional single image. No raw-byte logs."""
import errno
import hashlib
import json
import fcntl
import os
import re
from pathlib import Path
import struct
import subprocess
import sys
import time
import zlib

ROOT = Path(__file__).resolve().parents[1]
START = 0x4701
STATE = 0x80044702
CAPTURE = 0x4703
IDLE = 0x4704
SENSOR_IDENTITY = 0x80104705
ENGINE_METADATA = 0x80184706
RECEIVE_CHUNK = 1024


FACTORY_MODULE_SHA256 = '2149c3760637cc78663e4bc35314ea5aaf8ddecdab2b283ab9ca934a4cfd3cac'
FACTORY_STATUS_FIELDS = frozenset('''factory_otp_error factory_timing_valid factory_vendor_selection
factory_snapshot_error factory_snapshot_ready factory_prior_dac_matches factory_apply_error
factory_dac_readback_matches factory_config_crc_valid factory_restore_error factory_restored_registers'''.split())


class _OriginalBaselineCapture:
    """One checked frame, discarded after delivery; no stored pixel reference."""
    def __init__(self):
        self.requested = self.accepted = self.closed = False

    def next_capture(self):
        if self.closed or self.requested:
            return 0
        self.requested = True
        return 1

    def accept(self, pixels):
        if self.closed or not self.requested or self.accepted:
            raise RuntimeError('Unexpected original baseline image')
        self.accepted = True

    def close(self):
        self.closed = True


class _OriginalEngineCapture:
    """Validate and discard frames; the original enclaves own image state."""
    def __init__(self):
        self.pending = self.closed = False
        self.frames = 0

    def next_capture(self):
        if self.closed or self.frames >= 512:
            return 0
        self.pending = True
        return 1

    def accept(self, pixels):
        if self.closed or not self.pending or self.frames >= 512 or len(pixels) != 5120:
            raise RuntimeError('Unexpected original Engine frame')
        self.frames += 1
        self.pending = False

    def close(self):
        self.closed = True
        self.pending = False


class TlsBridge:
    def __init__(self, report, allow_capture=False, capture_session=False, enroll_finger=None, automatic=False, verify_candidate=False, image_consumer=None, native_session=None, factory_calibration=False, original_engine_baseline=False, original_engine_session=False):
        if type(original_engine_baseline) is not bool:
            raise ValueError('Original baseline scope must be explicit')
        if type(original_engine_session) is not bool or (original_engine_session and (
                not allow_capture or capture_session or enroll_finger or automatic or
                verify_candidate or image_consumer is not None or native_session is not None or
                factory_calibration or original_engine_baseline)):
            raise ValueError('Original Engine session requires its isolated scope')
        if original_engine_baseline and (not allow_capture or capture_session or enroll_finger or
                automatic or verify_candidate or image_consumer is not None or
                native_session is not None or factory_calibration):
            raise ValueError('Original baseline requires its isolated single-capture scope')
        self.original_engine_baseline = original_engine_baseline
        self.original_engine_session = original_engine_session
        if original_engine_baseline or original_engine_session:
            factory_calibration = True
        self.report, self.fd, self.loaded = report, None, False
        self.factory_calibration = factory_calibration
        self.factory_status = {}
        self.module_name = 'gxfp51b7_factory' if factory_calibration else 'gxfp51b7_native'
        self.module_path = (ROOT / 'native-probe/factory-probe/gxfp51b7_factory.ko'
                            if factory_calibration else ROOT / 'native-probe/gxfp51b7_native.ko')
        if original_engine_baseline:
            self.module_name = 'gxfp51b7_engine'
            self.module_path = ROOT / 'native-probe/engine-probe/gxfp51b7_engine.ko'
        elif original_engine_session:
            self.module_name = 'gxfp51b7_engine_service'
            self.module_path = ROOT / 'native-probe/engine-service/gxfp51b7_engine_service.ko'
        if type(factory_calibration) is not bool or (factory_calibration and
                native_session is None and not original_engine_baseline and not original_engine_session):
            raise ValueError('Factory calibration requires a private native capture session')
        self.allow_capture = allow_capture
        self.image_consumer = image_consumer
        self.finished = False
        self.capture_started = False
        self.image_received = False
        self.image_count = 0
        self.session = None
        self.capture_limit = 512 if automatic else 38 if enroll_finger else 8 if capture_session else 1
        if original_engine_baseline:
            self.session = _OriginalBaselineCapture()
            self.capture_limit = 1
        elif original_engine_session:
            self.session = _OriginalEngineCapture()
            self.capture_limit = 512
        elif native_session is not None:
            if not allow_capture or capture_session or enroll_finger or automatic or verify_candidate:
                raise ValueError('Native capture session must be explicitly enabled on its own')
            self.session = native_session
            self.capture_limit = 512
        elif verify_candidate:
            from automatic_verify import AutomaticVerification
            self.session = AutomaticVerification(report)
        elif automatic:
            from automatic_enroll import AutomaticEnrollment
            self.session = AutomaticEnrollment(report, enroll_finger)
        elif enroll_finger:
            from enroll_session import EnrollSession
            self.session = EnrollSession(report, enroll_finger)
        elif capture_session:
            from capture_session import CaptureSession
            self.session = CaptureSession(report)
        if os.geteuid() != 0 or not (os.environ.get('PKEXEC_UID') == '1000' or
                                   os.environ.get('GXFP51B7_SERVICE') == '1'):
            raise RuntimeError('TLS transport must run through pkexec as the UID1000 desktop owner')
        if original_engine_baseline and os.environ.get('PKEXEC_UID') != '1000':
            raise RuntimeError('Original baseline requires local pkexec authentication')
        if factory_calibration:
            if os.environ.get('PKEXEC_UID') != '1000':
                # Production authorization is restricted to the root-owned,
                # hashed release installed for this service. A Work checkout
                # does not acquire factory authority merely from an env var.
                release = ROOT.resolve()
                if (os.environ.get('GXFP51B7_SERVICE') != '1' or
                        release.parent != Path('/opt/gxfp51b7/releases') or
                        not re.fullmatch(r'[0-9a-f]{16}', release.name)):
                    raise RuntimeError('Factory mode requires local authentication or an installed root service')
                for asset in (release, Path(__file__).resolve(), self.module_path):
                    info = asset.stat()
                    if info.st_uid != 0 or info.st_mode & 0o022:
                        raise RuntimeError('Factory service assets must be root owned and protected')
            expected_module_hash = FACTORY_MODULE_SHA256
            if original_engine_baseline or original_engine_session:
                relative_manifest = ('native-sgx/engine-service-build/build.json' if original_engine_session
                                     else 'native-sgx/engine-feasibility-build/baseline-build.json')
                manifest = json.loads((ROOT / relative_manifest).read_text())
                expected_scope = 'original-engine-service' if original_engine_session else 'original-engine-baseline'
                if manifest.get('schema') != 1 or manifest.get('probe') != expected_scope:
                    raise RuntimeError('Unexpected original Engine transport manifest')
                expected_module_hash = manifest.get('checked_files', {}).get(
                    str(self.module_path.relative_to(ROOT)), '')
                if not isinstance(expected_module_hash, str) or not re.fullmatch('[0-9a-f]{64}', expected_module_hash):
                    raise RuntimeError('Missing original baseline transport identity')
            if hashlib.sha256(self.module_path.read_bytes()).hexdigest() != expected_module_hash:
                raise RuntimeError('Factory transport changed since preparation')
        for name in ('gxfp51b7_native', 'gxfp51b7_probe', 'gxfp51b7_sealed', 'gxfp51b7_otp', 'gxfp51b7_factory', 'gxfp51b7_engine', 'gxfp51b7_engine_service'):
            if Path('/sys/module', name).exists():
                raise RuntimeError('A fingerprint test module is already loaded')
        for path in ('/sys/bus/platform/devices/GXFP51B7:00/driver',
                     '/sys/bus/pci/devices/0000:00:1f.0/driver'):
            if Path(path).exists():
                raise RuntimeError('A fingerprint transport device already has a driver')
        sys.path.insert(0, str(ROOT / 'analysis'))
        from btf_iova_layout import verify_layout
        verify_layout()
        self.report('tls_bridge_running_kernel_iova_layout_verified=1')
        try:
            subprocess.run(['/usr/bin/insmod', str(self.module_path),
                            'run=1', 'driver_startup=1', 'observe_mailbox=1',
                            'map_mailbox=1', 'iova_layout_verified=1', 'tls_stream=1',
                            'capture_limit=' + str(self.capture_limit)], check=True)
            self.loaded = True
            if 'tls_stream_registered=1' not in self.kernel_report():
                raise RuntimeError('Native stream probe did not register')
            for attempt in range(21):
                if Path('/dev/gxfp51b7_tls').exists():
                    break
                if attempt == 20:
                    raise RuntimeError('Native stream node did not appear')
                time.sleep(0.05)
            self.fd = os.open('/dev/gxfp51b7_tls', os.O_RDWR | os.O_CLOEXEC)
        except BaseException:
            if factory_calibration and Path('/sys/module', self.module_name).exists():
                self.loaded = True
            self.close()
            raise

    def kernel_report(self):
        directory = Path('/sys/module', self.module_name, 'parameters')
        return ''.join((directory / name).read_text().removesuffix('\n')
                       for name in ('report', 'report_tail', 'report_more', 'report_end') +
                                   tuple('report_' + str(i) for i in range(4, 16))
                       if (directory / name).exists())

    def sensor_identity(self):
        """Fetch retained, validated OTP[0:16]; the ioctl issues no sensor read."""
        if not self.original_engine_baseline:
            raise OSError(errno.EOPNOTSUPP, 'Sensor identity is outside this transport scope')
        if self.fd is None:
            raise OSError(errno.ENOTCONN, 'Original baseline transport is closed')
        identity = bytearray(16)
        try:
            result = fcntl.ioctl(self.fd, SENSOR_IDENTITY, identity, True)
            if result != 0 or len(identity) != 16:
                raise OSError(errno.EIO, 'Invalid retained sensor identity response')
            return identity
        except BaseException:
            identity[:] = b'\0' * len(identity)
            raise

    def engine_metadata(self):
        """Return only already-validated RAM SensorID and original FDT inputs."""
        if not self.original_engine_session:
            raise OSError(errno.EOPNOTSUPP, 'Engine metadata is outside this transport scope')
        if self.fd is None:
            raise OSError(errno.ENOTCONN, 'Original Engine transport is closed')
        output = bytearray(24)
        try:
            result = fcntl.ioctl(self.fd, ENGINE_METADATA, output, True)
            if (result != 0 or len(output) != 24 or struct.unpack_from('<HH', output) != (1, 24)
                    or output[23] != 1 or not struct.unpack_from('<H', output, 20)[0]):
                raise OSError(errno.EIO, 'Invalid retained Engine metadata response')
            return output
        except BaseException:
            output[:] = b'\0' * len(output)
            raise

    def call(self, operation, payload):
        """Return errno plus a bounded response; unknown operations fail closed."""
        try:
            if operation == 5 and not payload:
                self.close()
                self.finished = True
                return 0, b''
            if self.fd is None:
                return errno.ENOTCONN, b''
            if operation == 1 and not payload:
                fcntl.ioctl(self.fd, START)
                self.report('tls_bridge_sensor_session_started=1')
                return 0, b''
            if operation == 2 and 5 <= len(payload) <= 4092:
                if os.write(self.fd, payload) != len(payload):
                    return errno.EIO, b''
                self.report('tls_bridge_sent_record_bytes=' + str(len(payload)) +
                            ' record_type=' + str(payload[0]))
                return 0, b''
            if operation == 3 and len(payload) == 4:
                wanted, = struct.unpack('<I', payload)
                if not 1 <= wanted <= 0x7000:
                    return errno.EMSGSIZE, b''
                # mbedTLS accepts a short read and fetches the remainder.
                # Keep each virtual-UART reply below the default guest queue
                # size instead of bursting an entire encrypted image into it.
                data = os.read(self.fd, min(wanted, RECEIVE_CHUNK))
                self.report('tls_bridge_received_bytes=' + str(len(data)) +
                            ' requested_bytes=' + str(wanted))
                if not data:
                    return errno.EIO, b''
                return 0, data + struct.pack('<I', zlib.crc32(data))
            if operation == 4 and not payload:
                value = bytearray(4)
                fcntl.ioctl(self.fd, STATE, value, True)
                self.report('tls_bridge_sensor_connected_flag=' + str(struct.unpack('<i', value)[0]))
                return 0, value
            if operation == 6 and not payload and self.allow_capture:
                if self.capture_started or self.image_count >= self.capture_limit:
                    return errno.EBUSY, b''
                if self.session and self.session.next_capture() != 1:
                    return errno.EAGAIN, b''
                # The original chip-ID response from this very session must
                # identify ChicagoHS before issuing its fixed image command.
                if 'register_chip_id=0x002504 register_chip_id_verified=1' not in self.kernel_report():
                    return errno.ENODEV, b''
                fcntl.ioctl(self.fd, CAPTURE)
                self.capture_started = True
                self.report('capture_bridge_single_image_requested=1')
                return 0, b''
            if operation == 7 and self.allow_capture and self.capture_started and \
                    (self.session or not self.image_received) and len(payload) == 10564:
                from chicago_image import decode_source_packet, WIDTH, HEIGHT
                try:
                    pixels = decode_source_packet(payload)
                except ValueError:
                    self.report('capture_host_source_crc_valid=0')
                    return errno.EBADMSG, b''
                try:
                    total = sum(pixels)
                    count = len(pixels)
                    mean = total / count
                    variance = sum((value - mean) ** 2 for value in pixels) / count
                    self.report('capture_host_source_crc_valid=1 pixels=' + str(count) +
                                ' width=' + str(WIDTH) + ' height=' + str(HEIGHT))
                    self.report('capture_host_pixel_min=' + str(min(pixels)) +
                                ' max=' + str(max(pixels)) +
                                ' distinct=' + str(len(set(pixels))) +
                                ' stddev=' + format(variance ** 0.5, '.2f'))
                    if self.session:
                        self.session.accept(pixels)
                        fcntl.ioctl(self.fd, IDLE)
                        self.capture_started = False
                    if self.image_consumer is not None:
                        self.image_consumer(pixels)
                    self.image_count += 1
                    self.image_received = True
                finally:
                    for index in range(len(pixels)):
                        pixels[index] = 0
                    self.report('capture_host_decoded_pixels_erased=1 image_bytes_logged=0')
                return 0, b''
            if operation == 8 and not payload and self.original_engine_baseline:
                return 0, self.sensor_identity()
            if operation == 8 and not payload and self.session:
                return 0, struct.pack('<I', self.session.next_capture())
            if operation == 9 and not payload and self.original_engine_session:
                return 0, self.engine_metadata()
            return errno.EINVAL, b''
        except OSError as error:
            return error.errno or errno.EIO, b''

    def close(self):
        try:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
        finally:
            try:
                if self.session:
                    self.session.close()
            finally:
                if self.loaded:
                    try:
                        report = self.kernel_report().rstrip()
                        if self.factory_calibration:
                            from fprint_backend import numeric_status_line
                            for line in report.splitlines():
                                self.factory_status.update(numeric_status_line(line.encode('ascii'), FACTORY_STATUS_FIELDS))
                        self.report(report)
                    finally:
                        subprocess.run(['/usr/bin/rmmod', self.module_name], check=True)
                        self.loaded = False
                        self.report('tls_bridge_native_module_unloaded=1')
                    if Path('/sys/bus/platform/devices/GXFP51B7:00/driver').exists() or \
                            Path('/sys/bus/pci/devices/0000:00:1f.0/driver').exists():
                        raise RuntimeError('Temporary transport binding remained after removal')
                    if self.factory_calibration and 'factory_apply_error' in self.factory_status:
                        if self.factory_status.get('factory_restore_error') != 0 or \
                           self.factory_status.get('factory_restored_registers') != 7:
                            raise RuntimeError('Factory experiment register restoration failed')
