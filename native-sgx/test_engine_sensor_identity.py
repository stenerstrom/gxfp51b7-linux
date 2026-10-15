#!/usr/bin/env python3
"""Synthetic checks of the isolated, opt-in retained-OTP identity channel."""
import contextlib
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'sgx-vm'))
import tls_bridge
from tls_bridge import TlsBridge, _OriginalBaselineCapture, SENSOR_IDENTITY
from transport_server import REQUEST, REPLY, serve_transport
import run_trial

SYNTHETIC_ID = bytes(range(16))


class IdentityGetterTests(unittest.TestCase):
    def bridge(self, enabled=True, descriptor=99):
        bridge = object.__new__(TlsBridge)
        bridge.original_engine_baseline = enabled
        bridge.fd = descriptor
        bridge.session = None
        return bridge

    def test_retained_identity_is_exact_mutable_output(self):
        def fake_ioctl(fd, command, output, mutate):
            self.assertEqual((fd, command, mutate), (99, SENSOR_IDENTITY, True))
            self.assertEqual(len(output), 16)
            output[:] = SYNTHETIC_ID
            return 0
        with patch('tls_bridge.fcntl.ioctl', side_effect=fake_ioctl) as ioctl:
            status, identity = self.bridge().call(8, bytearray())
        self.assertEqual(status, 0)
        self.assertIsInstance(identity, bytearray)
        self.assertEqual(identity, SYNTHETIC_ID)
        ioctl.assert_called_once()

    def test_unsupported_scope_never_calls_ioctl(self):
        with patch('tls_bridge.fcntl.ioctl') as ioctl:
            with self.assertRaises(OSError) as raised:
                self.bridge(enabled=False).sensor_identity()
        self.assertEqual(raised.exception.errno, errno.EOPNOTSUPP)
        ioctl.assert_not_called()

    def test_closed_transport_never_calls_ioctl(self):
        with patch('tls_bridge.fcntl.ioctl') as ioctl:
            self.assertEqual(self.bridge(descriptor=None).call(8, b''), (errno.ENOTCONN, b''))
        ioctl.assert_not_called()

    def test_uninitialized_kernel_cache_is_not_replaced(self):
        with patch('tls_bridge.fcntl.ioctl', side_effect=OSError(errno.ENODATA, 'synthetic')):
            self.assertEqual(self.bridge().call(8, b''), (errno.ENODATA, b''))

    def test_wrong_length_or_partial_error_is_erased(self):
        for outcome in ('length', 'errno', 'result'):
            with self.subTest(outcome=outcome):
                buffers = []
                def fake_ioctl(fd, command, output, mutate):
                    buffers.append(output)
                    output[:] = SYNTHETIC_ID
                    if outcome == 'length':
                        output.append(42)
                    if outcome == 'errno':
                        raise OSError(errno.EIO, 'synthetic')
                    return 1 if outcome == 'result' else 0
                with patch('tls_bridge.fcntl.ioctl', side_effect=fake_ioctl):
                    self.assertEqual(self.bridge().call(8, b''), (errno.EIO, b''))
                self.assertFalse(any(buffers[0]))

    def test_request_payload_is_rejected(self):
        with patch('tls_bridge.fcntl.ioctl') as ioctl:
            self.assertEqual(self.bridge().call(8, b'x'), (errno.EINVAL, b''))
        ioctl.assert_not_called()


class IdentityRpcTests(unittest.TestCase):
    def sockets(self):
        client, server = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        client.settimeout(1)
        return client, server

    def test_default_rejects_identity_before_bridge(self):
        client, server = self.sockets()
        client.sendall(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 0))
        bridge = MagicMock()
        with self.assertRaisesRegex(ValueError, 'out of bounds'):
            serve_transport(server, bridge, time.monotonic() + 1, allow_capture=True)
        bridge.call.assert_not_called()

    def test_identity_mode_excludes_session_and_requires_capture(self):
        for options in ({'allow_sensor_identity': True},
                        {'allow_sensor_identity': True, 'allow_capture': True, 'allow_session': True},
                        {'allow_sensor_identity': 1, 'allow_capture': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                serve_transport(MagicMock(), MagicMock(), time.monotonic() + 1, **options)

    def test_exact_identity_sent_then_erased(self):
        client, server = self.sockets()
        client.sendall(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 0) +
                       REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        identity = bytearray(SYNTHETIC_ID)
        bridge = MagicMock()
        bridge.call.side_effect = [(0, identity), (0, b'')]
        self.assertEqual(serve_transport(server, bridge, time.monotonic() + 1,
                                       allow_capture=True, allow_sensor_identity=True), 2)
        self.assertEqual(client.recv(REPLY.size), REPLY.pack(b'GXTR', 0, 16))
        self.assertEqual(client.recv(16), SYNTHETIC_ID)
        self.assertEqual(client.recv(REPLY.size), REPLY.pack(b'GXTR', 0, 0))
        self.assertFalse(any(identity))

    def test_wrong_size_immutable_and_error_payloads_are_rejected(self):
        for status, reply in ((0, bytearray(15)), (0, bytearray(range(17))),
                              (0, SYNTHETIC_ID), (errno.EIO, bytearray(SYNTHETIC_ID))):
            with self.subTest(status=status, length=len(reply)):
                client, server = self.sockets()
                client.sendall(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 0))
                bridge = MagicMock()
                bridge.call.return_value = status, reply
                with self.assertRaisesRegex(ValueError, 'identity reply'):
                    serve_transport(server, bridge, time.monotonic() + 1,
                                    allow_capture=True, allow_sensor_identity=True)
                if isinstance(reply, bytearray):
                    self.assertFalse(any(reply))

    def test_identity_request_length_rejected(self):
        client, server = self.sockets()
        client.sendall(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 1))
        bridge = MagicMock()
        with self.assertRaisesRegex(ValueError, 'out of bounds'):
            serve_transport(server, bridge, time.monotonic() + 1,
                            allow_capture=True, allow_sensor_identity=True)
        bridge.call.assert_not_called()

    def test_identity_erased_on_socket_send_failure(self):
        identity = bytearray(SYNTHETIC_ID)
        bridge = MagicMock()
        bridge.call.return_value = 0, identity
        connection = MagicMock()
        connection.sendall.side_effect = OSError(errno.EPIPE, 'synthetic')
        with patch('transport_server.read_exact', side_effect=[
                bytearray(REQUEST.pack(b'GXTL', 8, b'\0' * 3, 0)), bytearray()]):
            with self.assertRaises(OSError):
                serve_transport(connection, bridge, time.monotonic() + 1,
                                allow_capture=True, allow_sensor_identity=True)
        self.assertFalse(any(identity))

    def test_baseline_idle_budget_is_opt_in(self):
        for baseline, idle_seconds in ((False, 5), (True, 60)):
            with self.subTest(baseline=baseline):
                operation = 8 if baseline else 1
                connection = MagicMock()
                bridge = MagicMock()
                bridge.call.side_effect = [(0, bytearray(16) if baseline else b''), (0, b'')]
                with patch('transport_server.time.monotonic', return_value=0), \
                        patch('transport_server.read_exact', side_effect=[
                            bytearray(REQUEST.pack(b'GXTL', operation, b'\0' * 3, 0)), bytearray(),
                            bytearray(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0)), bytearray()]):
                    self.assertEqual(serve_transport(connection, bridge, 100,
                        allow_capture=True, allow_sensor_identity=baseline), 2)
                self.assertEqual([c.args[0] for c in connection.settimeout.call_args_list],
                                 [100, idle_seconds])


class BaselineBridgeScopeTests(unittest.TestCase):
    def test_single_capture_discards_without_retaining_pixels(self):
        capture = _OriginalBaselineCapture()
        self.assertEqual(capture.next_capture(), 1)
        pixels = [123] * 5120
        capture.accept(pixels)
        self.assertEqual(capture.__dict__, {'requested': True, 'accepted': True, 'closed': False})
        self.assertEqual(capture.next_capture(), 0)
        with self.assertRaises(RuntimeError):
            capture.accept(pixels)
        capture.close()
        self.assertEqual(capture.next_capture(), 0)

    def test_scope_cannot_mix_with_other_sessions(self):
        for options in ({}, {'allow_capture': True, 'native_session': object()},
                        {'allow_capture': True, 'factory_calibration': True},
                        {'allow_capture': True, 'capture_session': True},
                        {'allow_capture': True, 'image_consumer': lambda _: None}):
            with self.subTest(options=options), patch('tls_bridge.os.geteuid') as uid:
                with self.assertRaisesRegex(ValueError, 'isolated'):
                    TlsBridge(lambda _: None, original_engine_baseline=True, **options)
                uid.assert_not_called()

    def test_service_environment_does_not_authorize_baseline(self):
        with patch('tls_bridge.os.geteuid', return_value=0), \
                patch.dict(os.environ, {'GXFP51B7_SERVICE': '1'}, clear=True), \
                patch('tls_bridge.subprocess.run') as process:
            with self.assertRaisesRegex(RuntimeError, 'local pkexec'):
                TlsBridge(lambda _: None, allow_capture=True, original_engine_baseline=True)
        process.assert_not_called()

    def test_dedicated_module_hash_is_required_before_module_loading(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'native-probe/engine-probe/gxfp51b7_engine.ko'
            module.parent.mkdir(parents=True)
            module.write_bytes(b'synthetic non-executable module')
            manifest = root / 'native-sgx/engine-feasibility-build/baseline-build.json'
            manifest.parent.mkdir(parents=True)
            data = {'schema': 1, 'probe': 'original-engine-baseline', 'checked_files': {
                'native-probe/engine-probe/gxfp51b7_engine.ko': '0' * 64}}
            manifest.write_text(json.dumps(data))
            with patch.object(tls_bridge, 'ROOT', root), patch('tls_bridge.os.geteuid', return_value=0), \
                    patch.dict(os.environ, {'PKEXEC_UID': '1000'}, clear=True), \
                    patch('tls_bridge.subprocess.run') as process:
                with self.assertRaisesRegex(RuntimeError, 'transport changed'):
                    TlsBridge(lambda _: None, allow_capture=True, original_engine_baseline=True)
            process.assert_not_called()

    def test_valid_dedicated_module_uses_one_capture_and_existing_restoration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            module = root / 'native-probe/engine-probe/gxfp51b7_engine.ko'
            module.parent.mkdir(parents=True)
            module.write_bytes(b'synthetic non-executable module')
            manifest = root / 'native-sgx/engine-feasibility-build/baseline-build.json'
            manifest.parent.mkdir(parents=True)
            data = {'schema': 1, 'probe': 'original-engine-baseline', 'checked_files': {
                'native-probe/engine-probe/gxfp51b7_engine.ko': hashlib.sha256(module.read_bytes()).hexdigest()}}
            manifest.write_text(json.dumps(data))
            sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'analysis'))
            import btf_iova_layout
            status = ('tls_stream_registered=1\nfactory_apply_error=0\n'
                      'factory_restore_error=0 factory_restored_registers=7\n')
            with patch.object(tls_bridge, 'ROOT', root), patch('tls_bridge.os.geteuid', return_value=0), \
                    patch.dict(os.environ, {'PKEXEC_UID': '1000'}, clear=True), \
                    patch.object(Path, 'exists', lambda path: str(path) == '/dev/gxfp51b7_tls'), \
                    patch.object(btf_iova_layout, 'verify_layout') as layout, \
                    patch.object(TlsBridge, 'kernel_report', return_value=status), \
                    patch('tls_bridge.os.open', return_value=99), patch('tls_bridge.os.close') as close, \
                    patch('tls_bridge.subprocess.run') as process:
                bridge = TlsBridge(lambda _: None, allow_capture=True, original_engine_baseline=True)
                self.assertEqual(bridge.module_name, 'gxfp51b7_engine')
                self.assertEqual(bridge.capture_limit, 1)
                self.assertIsInstance(bridge.session, _OriginalBaselineCapture)
                self.assertTrue(bridge.factory_calibration)
                bridge.close()
            layout.assert_called_once()
            close.assert_called_once_with(99)
            self.assertEqual(process.call_args_list[0].args[0][0:2], ['/usr/bin/insmod', str(module)])
            self.assertIn('capture_limit=1', process.call_args_list[0].args[0])
            self.assertEqual(process.call_args_list[1].args[0], ['/usr/bin/rmmod', 'gxfp51b7_engine'])
            self.assertEqual(bridge.factory_status['factory_restored_registers'], 7)

    def test_runner_selects_isolated_scope_only_when_explicit(self):
        epc, sealed = os.pipe()
        bridge = MagicMock()
        with patch('tls_bridge.TlsBridge', return_value=bridge) as constructor, \
                patch('transport_server.serve_transport', return_value=1) as server, \
                patch.object(run_trial.os, 'fork', return_value=1234567), \
                patch.object(run_trial.os, 'waitpid', return_value=(1234567, 0)):
            self.assertEqual(run_trial.run_tls_trial(epc, sealed, capture=True,
                report=lambda _: None, runner_factory=lambda *args: ['synthetic'],
                allow_sensor_identity=True), 0)
        self.assertIs(constructor.call_args.kwargs['original_engine_baseline'], True)
        self.assertIs(server.call_args.kwargs['allow_sensor_identity'], True)
        bridge.close.assert_called_once()

    def test_parent_deadlines_change_only_for_baseline(self):
        for baseline, worker_seconds, rpc_seconds in ((False, 35, 45), (True, 125, 120)):
            with self.subTest(baseline=baseline):
                epc, sealed = os.pipe()
                bridge = MagicMock()
                with patch('tls_bridge.TlsBridge', return_value=bridge), \
                        patch('transport_server.serve_transport', side_effect=EOFError()) as server, \
                        patch.object(run_trial.os, 'fork', return_value=1234567), \
                        patch.object(run_trial.time, 'monotonic', return_value=10), \
                        patch.object(run_trial, 'reap_worker', return_value=1) as reap:
                    with self.assertRaises(EOFError):
                        run_trial.run_tls_trial(epc, sealed, capture=True,
                            report=lambda _: None, runner_factory=lambda *args: ['synthetic'],
                            allow_sensor_identity=baseline)
                self.assertEqual(server.call_args.args[2], 10 + rpc_seconds)
                reap.assert_called_once_with(1234567, 10 + worker_seconds)
                bridge.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
