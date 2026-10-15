"""Original Engine parent/control tests using synthetic buffers and fake I/O."""
import errno
import os
import struct
import unittest
from unittest.mock import MagicMock, patch

import engine_v2_protocol as p
from engine_reader import (EngineReader, UnreapedWorker, runner_arguments, default_bridge,
                           engine_status_and_close, SESSION_LOG_LIMIT, session_log)
from test_engine_v2_protocol import MemorySocket, encoded_reply
from transport_server import REQUEST, REPLY, serve_transport_once


def restored_status():
    return dict(factory_otp_error=0, factory_timing_valid=1, factory_vendor_selection=1,
                factory_snapshot_error=0, factory_snapshot_ready=1, factory_prior_dac_matches=0,
                factory_apply_error=0, factory_dac_readback_matches=4, factory_config_crc_valid=1,
                factory_restore_error=0, factory_restored_registers=7)


class EngineReaderTests(unittest.TestCase):
    def test_service_log_keeps_numeric_stage_context_and_erases_everything_else(self):
        fd = session_log()
        observer = os.dup(fd)
        try:
            os.pwrite(fd, b'pair_side=0 dh_ecall=62 sgx_result=0 application_result=0 output_length=576\n'
                      b'engine_ecall_number=17 sgx_result=0x4001 ocalls=0\n'
                      b'original_engine_service_result=5 frames=3 discarded_adaptive_update=0\n'
                      b'original_engine_service_result=0 secret_payload=12345\n'
                      b'raw template contents must never appear\n', 0)
            status, records = engine_status_and_close(fd)
            self.assertEqual(status['original_engine_service_result'], 5)
            self.assertEqual(status['engine_ecall_number'], 17)
            self.assertEqual(status['sgx_result'], 0x4001)
            self.assertEqual(records[0]['pair_side'], 0)
            self.assertEqual(records[0]['dh_ecall'], 62)
            self.assertEqual(len(records), 3)
            self.assertNotIn('secret_payload', status)
            self.assertFalse(any(os.pread(observer, SESSION_LOG_LIMIT, 0)))
        finally:
            os.close(observer)

    def test_service_log_record_count_is_bounded(self):
        fd = session_log()
        os.pwrite(fd, b'engine_ecall_number=17 sgx_result=0 ocalls=0\n' * 200, 0)
        status, records = engine_status_and_close(fd)
        self.assertEqual(len(records), 128)
        self.assertEqual(status['engine_ecall_number'], 17)

    def test_runner_argv_exact_descriptor_order(self):
        args = runner_arguments(10, 11, 12, 13)
        self.assertEqual(len(args), 10)
        self.assertTrue(args[0].endswith('/engine-service-build/engine_service_runner'))
        self.assertEqual((args[1], args[7], args[8], args[9]), ('10', '11', '12', '13'))
        with self.assertRaises(ValueError):
            runner_arguments(10, -1, 12, 13)

    def test_start_failure_releases_protected_input_epc_and_ram_log(self):
        sealed = os.memfd_create('synthetic-engine-sealed-start')
        epc = os.memfd_create('synthetic-engine-epc-start')
        reader = EngineReader(report=lambda _: None,
                              bridge_factory=MagicMock(side_effect=OSError(errno.EIO, 'synthetic bridge failure')))
        with patch('engine_reader.create_sealed_input', return_value=sealed), \
                patch('engine_reader.os.open', return_value=epc), \
                patch('engine_reader.os.fork') as fork:
            with self.assertRaises(OSError):
                reader.start()
        fork.assert_not_called()
        for fd in (sealed, epc):
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual((reader.sealed_fd, reader.epc_fd, reader.log_fd), (-1, -1, -1))

    def test_parent_closes_inherited_fd_copies_after_successful_fork(self):
        sealed = os.memfd_create('synthetic-engine-sealed-fork')
        epc = os.memfd_create('synthetic-engine-epc-fork')
        bridge = MagicMock(factory_status=restored_status())
        reader = EngineReader(report=lambda _: None, bridge_factory=lambda *args: bridge)
        with patch('engine_reader.create_sealed_input', return_value=sealed), \
                patch('engine_reader.os.open', return_value=epc), \
                patch('engine_reader.os.fork', return_value=1234):
            reader.start()
        self.assertEqual(reader.pid, 1234)
        self.assertIsNone(reader.transport_child)
        self.assertIsNone(reader.control_child)
        for fd in (sealed, epc):
            with self.assertRaises(OSError):
                os.fstat(fd)
        with patch('engine_reader.reap_worker', return_value=0):
            reader.close(graceful=False)
        bridge.close.assert_called_once()

    def test_bridge_scope_uses_only_the_private_engine_collector(self):
        with patch('tls_bridge.TlsBridge') as bridge:
            report = lambda _: None
            default_bridge(report)
        bridge.assert_called_once_with(report, allow_capture=True, original_engine_session=True)

    def test_multiple_retry_steps_keep_one_worker_and_private_session(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid = 123
        reader.session_id = 9
        reader.transport = MemorySocket()
        for index, event in enumerate((p.WAIT_FINGER, p.WAIT_REMOVE, p.RETRY, p.MATCH), 1):
            reader.control = MemorySocket(encoded_reply(p.Reply(p.STEP, index, 9, event=event)))
            with patch('engine_reader.select.select', return_value=([reader.control], [], [])), \
                    patch.object(reader, 'start') as start:
                result = reader.request(p.STEP)
                self.assertEqual(result.event, event)
                self.assertEqual(reader.pid, 123)
                start.assert_not_called()
        self.assertEqual(reader.sequence, 4)

    def test_sensor_rpc_is_serviced_while_waiting_for_control(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        reader.control = MemorySocket(encoded_reply(p.Reply(p.STEP, 1, 9, event=p.WAIT_FINGER)))
        reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 4, b'\0' * 3, 0))
        reader.bridge = MagicMock()
        reader.bridge.call.return_value = (0, bytearray(struct.pack('<I', 1)))
        with patch('engine_reader.select.select', side_effect=[([reader.transport], [], []),
                                                              ([reader.control], [], [])]):
            reply = reader.request(p.STEP)
        self.assertEqual(reply.event, p.WAIT_FINGER)
        self.assertEqual(reader.requests, 1)
        self.assertEqual(REPLY.unpack(reader.transport.sent[:12]), (b'GXTR', 0, 4))

    def test_cancelled_exchange_closes_worker_and_sensor(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        reader.control = MemorySocket(encoded_reply(p.Reply(p.CLOSE_SESSION, 1, 9, event=p.CLOSED)))
        reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.call.return_value = (0, b'')
        bridge = reader.bridge
        with patch('engine_reader.reap_worker', return_value=0) as reap, \
                patch('engine_reader.select.select', return_value=([reader.transport, reader.control], [], [])):
            with self.assertRaises(OSError) as error:
                reader.request(p.STEP, cancelled=lambda: True)
        self.assertEqual(error.exception.errno, errno.ECANCELED)
        bridge.close.assert_called_once()
        reap.assert_called_once()
        self.assertTrue(reader.closed)

    def test_disconnect_drains_one_inflight_step_then_closes_without_another_capture(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        control = reader.control = MemorySocket(
            encoded_reply(p.Reply(p.STEP, 1, 9, event=p.WAIT_FINGER)) +
            encoded_reply(p.Reply(p.CLOSE_SESSION, 2, 9, event=p.CLOSED)))
        transport = reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.call.return_value = (0, b'')
        checks = iter([False, False, True])
        def cancelled():
            return next(checks, True)
        with patch('engine_reader.reap_worker', return_value=0), \
                patch('engine_reader.select.select', side_effect=[([control], [], []),
                                                                  ([transport, control], [], [])]):
            with self.assertRaises(OSError) as error:
                reader.request(p.STEP, cancelled=cancelled)
        self.assertEqual(error.exception.errno, errno.ECANCELED)
        sent = MemorySocket(control.sent)
        self.assertEqual(p.read_request(sent).operation, p.STEP)
        self.assertEqual(p.read_request(sent).operation, p.CLOSE_SESSION)
        self.assertEqual(sent.position, len(sent.incoming))
        self.assertEqual(reader.last_exit_code, 0)

    def test_cancel_before_open_never_launches_or_reads_protected_input(self):
        reader = EngineReader(report=lambda _: None)
        with patch.object(reader, 'start') as start, \
                patch('engine_reader.create_sealed_input') as sealed:
            with self.assertRaises(OSError):
                reader.request(p.OPEN_SESSION, cancelled=lambda: True)
        start.assert_not_called()
        sealed.assert_not_called()

    def test_cleanup_failures_remain_errors_and_close_owned_fds(self):
        reader = EngineReader(report=lambda _: None)
        reader.epc_fd = os.memfd_create('synthetic-engine-epc')
        reader.sealed_fd = os.memfd_create('synthetic-engine-sealed')
        owned = [reader.epc_fd, reader.sealed_fd]
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.close.side_effect = OSError(errno.EIO, 'synthetic restoration failure')
        with self.assertRaises(OSError):
            reader.close(graceful=False)
        for fd in owned:
            with self.assertRaises(OSError):
                os.fstat(fd)
        with self.assertRaises(OSError):
            reader.close()
        self.assertNotEqual(reader.last_exit_code, 0)

    def test_unreaped_child_is_fatal_after_remaining_cleanup(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid = 123
        reader.bridge = MagicMock(factory_status=restored_status())
        bridge = reader.bridge
        with patch('engine_reader.reap_worker', side_effect=RuntimeError('synthetic deadline')):
            with self.assertRaises(UnreapedWorker):
                reader.close(graceful=False)
        bridge.close.assert_called_once()
        self.assertTrue(reader.closed)
        self.assertIsNone(reader.bridge)

    def test_end_action_reaps_before_forwarding_close(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        reader.control = MemorySocket(encoded_reply(p.Reply(p.END_ACTION, 1, 9, event=p.CLOSED)))
        reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.call.return_value = (0, b'')
        with patch('engine_reader.select.select', return_value=([reader.transport, reader.control], [], [])), \
                patch('engine_reader.reap_worker', return_value=0) as reap:
            reply = reader.request(p.END_ACTION)
        self.assertEqual(reply.event, p.CLOSED)
        self.assertTrue(reader.closed)
        self.assertEqual(reader.last_exit_code, 0)
        reap.assert_called_once()

    def test_retained_retry_keeps_one_private_worker_across_verify_actions(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        control = reader.control = MemorySocket(b''.join(encoded_reply(reply) for reply in [
            p.Reply(p.STEP, 1, 9, event=p.RETRY),
            p.Reply(p.END_ACTION, 2, 9, event=p.CLOSED, flags=p.RETRY_SESSION_RETAINED),
            p.Reply(p.BEGIN_VERIFY, 3, 9),
            p.Reply(p.STEP, 4, 9, event=p.WAIT_REMOVE),
            p.Reply(p.STEP, 5, 9, event=p.WAIT_FINGER),
            p.Reply(p.STEP, 6, 9, event=p.MATCH),
            p.Reply(p.END_ACTION, 7, 9, event=p.CLOSED),
        ]))
        reader.transport = MemorySocket()
        reader.bridge = MagicMock(factory_status=restored_status())
        started = reader.started
        with patch('engine_reader.select.select', return_value=([control], [], [])), \
                patch('engine_reader.reap_worker', return_value=0) as reap:
            self.assertEqual(reader.request(p.STEP).event, p.RETRY)
            ended = reader.request(p.END_ACTION)
            self.assertEqual(ended.flags, p.RETRY_SESSION_RETAINED)
            self.assertFalse(reader.closed)
            self.assertEqual(reader.pid, 123)
            reap.assert_not_called()
            reader.request(p.BEGIN_VERIFY, bytearray(b'x' * p.TEMPLATE_MIN))
            for event in (p.WAIT_REMOVE, p.WAIT_FINGER, p.MATCH):
                self.assertEqual(reader.request(p.STEP).event, event)
            self.assertEqual(reader.started, started)
            reader.request(p.END_ACTION)
        self.assertTrue(reader.closed)
        reap.assert_called_once()
        sent = MemorySocket(control.sent)
        operations = []
        while sent.position < len(sent.incoming):
            request = p.read_request(sent)
            operations.append(request.operation)
            self.assertEqual(request.session_id, 9)
            request.close()
        self.assertEqual(operations, [p.STEP, p.END_ACTION, p.BEGIN_VERIFY,
                                      p.STEP, p.STEP, p.STEP, p.END_ACTION])

    def test_cancellation_after_retained_reply_closes_and_reaps_before_return(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        control = reader.control = MemorySocket(
            encoded_reply(p.Reply(p.END_ACTION, 1, 9, event=p.CLOSED, flags=p.RETRY_SESSION_RETAINED)) +
            encoded_reply(p.Reply(p.CLOSE_SESSION, 2, 9, event=p.CLOSED)))
        transport = reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.call.return_value = (0, b'')
        checks = iter([False, False, False, True])
        with patch('engine_reader.select.select', side_effect=[([control], [], []),
                                                              ([transport, control], [], [])]), \
                patch('engine_reader.reap_worker', return_value=0) as reap:
            with self.assertRaises(OSError) as error:
                reader.request(p.END_ACTION, cancelled=lambda: next(checks, True))
        self.assertEqual(error.exception.errno, errno.ECANCELED)
        self.assertTrue(reader.closed)
        reap.assert_called_once()
        sent = MemorySocket(control.sent)
        self.assertEqual(p.read_request(sent).operation, p.END_ACTION)
        self.assertEqual(p.read_request(sent).operation, p.CLOSE_SESSION)
        self.assertEqual(sent.position, len(sent.incoming))

    def test_retained_flag_cannot_hide_a_finished_transport(self):
        reader = EngineReader(report=lambda _: None)
        reader.pid, reader.session_id = 123, 9
        reader.control = MemorySocket(encoded_reply(
            p.Reply(p.END_ACTION, 1, 9, event=p.CLOSED, flags=p.RETRY_SESSION_RETAINED)))
        reader.transport = MemorySocket(REQUEST.pack(b'GXTL', 5, b'\0' * 3, 0))
        reader.bridge = MagicMock(factory_status=restored_status())
        reader.bridge.call.return_value = (0, b'')
        with patch('engine_reader.select.select', return_value=([reader.transport, reader.control], [], [])), \
                patch('engine_reader.reap_worker', return_value=0) as reap:
            with self.assertRaises(OSError) as error:
                reader.request(p.END_ACTION)
        self.assertEqual(error.exception.errno, errno.EPROTO)
        self.assertTrue(reader.closed)
        reap.assert_called_once()

    def test_metadata_scope_is_opt_in_and_erases_reply(self):
        header = REQUEST.pack(b'GXTL', 9, b'\0' * 3, 0)
        with self.assertRaises(ValueError):
            serve_transport_once(MemorySocket(header), MagicMock(), 1, allow_capture=True, allow_session=True)
        metadata = bytearray(struct.pack('<HH16sHBB', 1, 24, b'x' * 16, 42, 17, 1))
        bridge = MagicMock()
        bridge.call.return_value = (0, metadata)
        connection = MemorySocket(header)
        self.assertEqual(serve_transport_once(connection, bridge, 1, allow_capture=True,
                                              allow_session=True, allow_engine_metadata=True), (9, 0))
        self.assertEqual(REPLY.unpack(connection.sent[:12]), (b'GXTR', 0, 24))
        self.assertFalse(any(metadata))

    def test_bad_metadata_never_crosses_socket_and_is_erased(self):
        for size, version, flags in ((23, 1, 1), (24, 2, 1), (24, 1, 0)):
            data = bytearray(struct.pack('<HH16sHBB', version, 24, b'x' * 16, 42, 17, flags))[:size]
            bridge = MagicMock()
            bridge.call.return_value = (0, data)
            connection = MemorySocket(REQUEST.pack(b'GXTL', 9, b'\0' * 3, 0))
            with self.assertRaises(ValueError):
                serve_transport_once(connection, bridge, 1, allow_capture=True,
                                     allow_session=True, allow_engine_metadata=True)
            self.assertFalse(connection.sent)
            self.assertFalse(any(data))


if __name__ == '__main__':
    unittest.main()
