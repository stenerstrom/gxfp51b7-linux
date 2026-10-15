"""Session control, authenticated-image boundaries and cleanup without hardware."""
from array import array
import contextlib
import errno
import socket
import struct
import sys
import time
import unittest
from unittest.mock import MagicMock, patch
from pathlib import Path

from persistent_reader import (CaptureController, PersistentReader, MAX_FRAMES,
                               session_log, session_status_and_close, SESSION_LOG_LIMIT)
import os
from transport_server import REQUEST, REPLY, serve_transport

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'sgx-vm'))


class NativeSessionTests(unittest.TestCase):
    def test_long_session_log_is_sealed_and_exports_only_numeric_status(self):
        fd = session_log()
        observer = os.dup(fd)
        try:
            os.pwrite(fd, b'trial_result=0 invalid_mac_callbacks=0\ntrial_result=1234 secret_value=1234\n', 0)
            os.pwrite(fd, b'\ntls_final_connected_callbacks=1\n', SESSION_LOG_LIMIT - 100)
            with self.assertRaises(OSError):
                os.ftruncate(fd, SESSION_LOG_LIMIT + 1)
            status = session_status_and_close(fd)
            self.assertEqual(status.get('trial_result'), 0)
            self.assertEqual(status.get('invalid_mac_callbacks'), 0)
            self.assertEqual(status.get('tls_final_connected_callbacks'), 1)
            self.assertNotIn('secret_value', status)
            self.assertFalse(any(os.pread(observer, SESSION_LOG_LIMIT, 0)))
        finally:
            os.close(observer)

    def test_each_request_accepts_one_bounded_image(self):
        controller = CaptureController()
        for unused in range(3):
            controller.request(1)
            self.assertEqual(controller.next_capture(), 1)
            self.assertEqual(controller.next_capture(), 1)
            controller.accept([1234] * 5120)
            with self.assertRaises(RuntimeError):
                controller.accept([1234] * 5120)
            pixels = controller.take()
            self.assertEqual(list(pixels), [1234] * 5120)
        controller.request(2)
        self.assertEqual(controller.next_capture(), 2)
        with self.assertRaises(RuntimeError):
            controller.request(1)
        controller.close()

    def test_order_bounds_and_failure_clear_pending_image(self):
        controller = CaptureController()
        with self.assertRaises(RuntimeError):
            controller.accept([1] * 5120)
        with self.assertRaises(RuntimeError):
            controller.next_capture()
        controller.request(1)
        controller.next_capture()
        for image in ([1], [4096] * 5120, [-1] * 5120):
            with self.assertRaises(RuntimeError):
                controller.accept(image)
        controller.accept([1] * 5120)
        pixels = controller.pixels
        controller.close()
        self.assertFalse(any(pixels))
        controller.frames = MAX_FRAMES
        with self.assertRaises(RuntimeError):
            controller.request(1)

    def test_rpc_session_is_explicit_and_never_accepts_capture_payloads(self):
        client, connection = socket.socketpair()
        with client, connection:
            for options in ({'allow_session': True}, {'stop_after_image': True},
                            {'allow_capture': True, 'stop_after_image': True}):
                with self.assertRaises(ValueError):
                    serve_transport(connection, MagicMock(), time.monotonic() + 1, **options)
        for operation, length, session in ((8, 0, False), (8, 1, True), (6, 1, True), (7, 10565, True)):
            with self.subTest(operation=operation, length=length), contextlib.ExitStack() as stack:
                client, server = socket.socketpair()
                stack.callback(client.close)
                stack.callback(server.close)
                client.sendall(REQUEST.pack(b'GXTL', operation, b'\0' * 3, length))
                with self.assertRaises(ValueError):
                    serve_transport(server, MagicMock(), time.monotonic() + 1,
                                    allow_capture=True, allow_session=session)

    def test_transport_yields_only_after_successful_checked_image(self):
        client, server = socket.socketpair()
        try:
            client.sendall(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 0) +
                           REQUEST.pack(b'GXTL', 7, b'\0' * 3, 10564) + b'\0' * 10564)
            bridge = MagicMock()
            bridge.call.side_effect = [(0, struct.pack('<I', 1)), (0, b'')]
            count = serve_transport(server, bridge, time.monotonic() + 1,
                                    allow_capture=True, allow_session=True, stop_after_image=True)
            self.assertEqual(count, 2)
            self.assertEqual(bridge.call.call_count, 2)
            # read_exact()'s mutable payload is erased even after bridge.call.
            self.assertFalse(any(bridge.call.call_args_list[-1].args[1]))
        finally:
            client.close()
            server.close()

    def test_native_session_cannot_enable_other_capture_modes(self):
        from tls_bridge import TlsBridge
        for options in ({}, {'allow_capture': True, 'automatic': True},
                        {'allow_capture': True, 'capture_session': True}):
            with self.assertRaises(ValueError):
                TlsBridge(lambda _: None, native_session=CaptureController(), **options)

    def test_rpc_failure_closes_transport_and_reaps_without_signals(self):
        reader = PersistentReader(report=lambda _: None)
        reader.parent = MagicMock()
        reader.bridge = MagicMock()
        reader.pid = 1234567
        with patch('persistent_reader.serve_transport', side_effect=EOFError()), \
             patch('persistent_reader.reap_worker', return_value=1) as reap, \
             patch('persistent_reader.os.kill') as kill:
            with self.assertRaises(EOFError):
                reader.capture()
        reap.assert_called_once()
        kill.assert_not_called()
        self.assertTrue(reader.closed)
        self.assertEqual(reader.close(), 1)
        reap.assert_called_once()  # Repeated close preserves status without another reap.
        self.assertIsNone(reader.parent)
        self.assertFalse(reader.controller.pending)

    def test_finished_transport_never_returns_an_image_from_failed_session(self):
        reader = PersistentReader(report=lambda _: None)
        reader.parent = MagicMock()
        reader.bridge = MagicMock(finished=True)
        reader.controller.pixels = array('H', [1] * 5120)
        # Install the pixels during the simulated RPC, after request(1).
        pixels = reader.controller.pixels
        reader.controller.pixels = None
        def finished(*args, **kwargs):
            reader.controller.pixels = pixels
            reader.controller.pending = False
            return 2
        with patch('persistent_reader.serve_transport', side_effect=finished):
            with self.assertRaises(OSError) as raised:
                reader.capture()
        self.assertEqual(raised.exception.errno, errno.EIO)
        self.assertFalse(any(pixels))

    def test_ram_log_failure_still_closes_all_owned_input_fds(self):
        reader = PersistentReader(report=lambda _: None)
        reader.log_fd = session_log()
        reader.epc_fd = os.memfd_create('synthetic-epc')
        reader.sealed_fd = os.memfd_create('synthetic-sealed')
        owned = [reader.log_fd, reader.epc_fd, reader.sealed_fd]
        def fail_after_closing_log(fd):
            os.close(fd)
            raise OSError(errno.EIO, 'Synthetic RAM log erasure failure')
        try:
            with patch('persistent_reader.session_status_and_close', side_effect=fail_after_closing_log):
                with self.assertRaises(OSError): reader.close()
            for fd in owned:
                with self.assertRaises(OSError) as raised: os.fstat(fd)
                self.assertEqual(raised.exception.errno, errno.EBADF)
            self.assertEqual((reader.log_fd, reader.epc_fd, reader.sealed_fd), (-1, -1, -1))
            self.assertNotEqual(reader.close(), 0)
        finally:
            for fd in owned:
                try: os.close(fd)
                except OSError: pass

    def test_bridge_cleanup_exception_remains_failure_on_repeated_close(self):
        reader = PersistentReader(report=lambda _: None)
        reader.parent = MagicMock(); reader.pid = 1234567
        reader.bridge = MagicMock(factory_status={})
        reader.bridge.close.side_effect = RuntimeError('Synthetic unload failure')
        with patch('persistent_reader.serve_transport', side_effect=EOFError()), \
             patch('persistent_reader.reap_worker', return_value=0) as reap:
            with self.assertRaises(RuntimeError): reader.close()
            self.assertNotEqual(reader.close(), 0)
            reap.assert_called_once()


if __name__ == '__main__':
    unittest.main()
