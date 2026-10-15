"""Exercise the candidate metadata ioctl and bounded RAM-only capture scope."""
import errno
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'sgx-vm'))
from tls_bridge import TlsBridge, _OriginalEngineCapture, ENGINE_METADATA


class MetadataTests(unittest.TestCase):
    def bridge(self, enabled=True):
        bridge = object.__new__(TlsBridge)
        bridge.original_engine_session = enabled
        bridge.original_engine_baseline = False
        bridge.fd = 99
        bridge.session = _OriginalEngineCapture()
        return bridge

    def test_exact_metadata_is_mutable_and_separate_from_capture_control(self):
        expected = struct.pack('<HH16sHBB', 1, 24, bytes(range(16)), 320, 28, 1)
        def ioctl(fd, operation, out, mutate):
            self.assertEqual((fd, operation, mutate), (99, ENGINE_METADATA, True))
            out[:] = expected
            return 0
        bridge = self.bridge()
        with patch('tls_bridge.fcntl.ioctl', side_effect=ioctl) as call:
            status, data = bridge.call(9, b'')
            self.assertEqual((status, data), (0, expected))
            self.assertIsInstance(data, bytearray)
            self.assertEqual(bridge.call(8, b''), (0, struct.pack('<I', 1)))
            call.assert_called_once()

    def test_bad_metadata_erased_before_error(self):
        for index in (0, 2, 20, 23):
            captured = []
            def ioctl(fd, operation, out, mutate):
                out[:] = struct.pack('<HH16sHBB', 1, 24, b'X' * 16, 80, 28, 1)
                out[index] = 0
                captured.append(out)
                return 0
            with patch('tls_bridge.fcntl.ioctl', side_effect=ioctl):
                self.assertEqual(self.bridge().call(9, b''), (errno.EIO, b''))
            self.assertFalse(any(captured[0]))

    def test_wrong_scope_and_payload_never_access_hardware(self):
        with patch('tls_bridge.fcntl.ioctl') as call:
            self.assertEqual(self.bridge(False).call(9, b''), (errno.EINVAL, b''))
            self.assertEqual(self.bridge().call(9, b'X'), (errno.EINVAL, b''))
            call.assert_not_called()

    def test_capture_limit_and_erasure_ownership(self):
        capture = _OriginalEngineCapture()
        pixels = [123] * 5120
        for _ in range(512):
            self.assertEqual(capture.next_capture(), 1)
            self.assertEqual(capture.next_capture(), 1)
            capture.accept(pixels)
        self.assertEqual(capture.next_capture(), 0)
        self.assertEqual(set(vars(capture)), {'pending', 'closed', 'frames'})
        with self.assertRaises(RuntimeError):
            capture.accept(pixels)
        capture.close()
        self.assertEqual(capture.next_capture(), 0)

    def test_mixed_scope_rejected_before_root_or_hardware(self):
        for options in ({}, {'allow_capture': True, 'original_engine_baseline': True},
                        {'allow_capture': True, 'native_session': object()},
                        {'allow_capture': True, 'factory_calibration': True}):
            with self.subTest(options=options), patch('tls_bridge.os.geteuid') as uid:
                with self.assertRaises(ValueError):
                    TlsBridge(lambda _: None, original_engine_session=True, **options)
                uid.assert_not_called()


if __name__ == '__main__':
    unittest.main()
