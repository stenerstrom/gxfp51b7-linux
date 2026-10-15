"""Candidate claim, retry, cancellation and owner cleanup tests without hardware."""
import errno
import types
import unittest
from unittest.mock import MagicMock, patch

import engine_v2_protocol as p
from engine_backend import EngineBackend, process_identity, main
from test_engine_v2_protocol import MemorySocket


class FakeReader:
    def __init__(self, events=None, retain_retries=False):
        self.calls = []
        self.close_calls = 0
        self.events = list(events or [])
        self.closed = False
        self.failure = None
        self.retain_retries = retain_retries
        self.action = self.last_event = None

    def request(self, operation, payload=None, cancelled=lambda: False):
        self.calls.append(operation)
        if self.failure:
            raise self.failure
        if cancelled():
            raise OSError(errno.ECANCELED, 'synthetic disconnect')
        event = self.events.pop(0) if operation == p.STEP else (
            p.CLOSED if operation in (p.END_ACTION, p.CLOSE_SESSION) else p.READY)
        if operation in (p.BEGIN_ENROLL, p.BEGIN_VERIFY):
            self.action, self.last_event = operation, None
        elif operation == p.STEP:
            self.last_event = event
        flags = (4 if self.retain_retries and operation == p.END_ACTION and
                 self.action == p.BEGIN_VERIFY and self.last_event == p.RETRY else 0)
        if operation == p.END_ACTION:
            self.action = self.last_event = None
        blob = bytearray(b'x' * p.TEMPLATE_MIN) if event == p.ENROLL_COMPLETE else bytearray()
        return p.Reply(operation, 1, 99, event=event, flags=flags, blob=blob)

    def close(self):
        self.close_calls += 1
        self.closed = True


class BackendTests(unittest.TestCase):
    owner = (100, 5000)

    def make(self, events=None, retain_retries=False):
        created = []
        def factory():
            created.append(FakeReader(events, retain_retries))
            return created[-1]
        backend = EngineBackend(reader_factory=factory, token_factory=lambda: 777,
                                identity_reader=lambda pid: self.owner)
        return backend, created

    def request(self, backend, operation, sequence, session=777, payload=None):
        return backend.process(p.Request(operation, sequence, session,
                                         payload if payload is not None else bytearray()), self.owner)

    def test_descriptor_never_opens_worker(self):
        backend, created = self.make()
        result = self.request(backend, p.DESCRIBE, 1, 0)
        self.assertEqual((result.target, result.quality, result.coverage), (20, 12, p.TEMPLATE_MAX))
        self.assertEqual(result.flags, p.ADAPTIVE_UPDATE_DISCARDED | p.REQUIRES_EMPTY_START)
        self.assertFalse(created)

    def test_one_worker_survives_all_enrollment_retry_frames(self):
        backend, created = self.make([p.WAIT_REMOVE, p.RETRY, p.ENROLL_ACCEPTED, p.ENROLL_COMPLETE])
        opened = self.request(backend, p.OPEN_SESSION, 1, 0)
        self.assertEqual(opened.session_id, 777)
        self.request(backend, p.BEGIN_ENROLL, 2)
        for sequence in range(3, 7):
            reply = self.request(backend, p.STEP, sequence)
            self.assertEqual(reply.request_id, sequence)
        self.assertEqual(reply.event, p.ENROLL_COMPLETE)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].calls.count(p.OPEN_SESSION), 1)
        self.assertEqual(created[0].close_calls, 0)
        reply.close()
        self.request(backend, p.END_ACTION, 7)
        self.assertTrue(created[0].closed)
        self.assertEqual(backend.phase, 'idle')
        self.assertEqual(backend.session_id, 777)
        self.request(backend, p.BEGIN_ENROLL, 8)
        self.assertEqual(len(created), 2)
        self.assertEqual(created[1].calls, [p.OPEN_SESSION, p.BEGIN_ENROLL])

    def test_owner_start_time_and_sequence_are_checked(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        for owner, sequence, session in (((101, 5000), 2, 777),
                                          ((100, 5001), 2, 777),
                                          (self.owner, 1, 777), (self.owner, 2, 778)):
            with self.subTest(owner=owner, sequence=sequence, session=session):
                with self.assertRaises(OSError):
                    backend.process(p.Request(p.BEGIN_ENROLL, sequence, session), owner)
        self.assertEqual(created[0].calls, [p.OPEN_SESSION])

    def test_daemon_verify_retry_reuses_the_worker_and_empty_baseline(self):
        # fprintd v1.94.5 verify_cb starts a new libfprint verify action on
        # FP_DEVICE_RETRY without releasing its claim. No sensor is involved.
        backend, created = self.make([p.RETRY, p.WAIT_REMOVE, p.WAIT_FINGER, p.MATCH],
                                     retain_retries=True)
        self.request(backend, p.OPEN_SESSION, 1, 0)
        template = bytearray(b'x' * p.TEMPLATE_MIN)
        self.request(backend, p.BEGIN_VERIFY, 2, payload=template)
        self.assertEqual(self.request(backend, p.STEP, 3).event, p.RETRY)
        ended = self.request(backend, p.END_ACTION, 4)
        self.assertEqual(ended.flags, 4)
        self.assertFalse(created[0].closed)
        self.assertIs(backend.reader, created[0])
        self.request(backend, p.BEGIN_VERIFY, 5, payload=template)
        for sequence, event in [(6, p.WAIT_REMOVE), (7, p.WAIT_FINGER), (8, p.MATCH)]:
            self.assertEqual(self.request(backend, p.STEP, sequence).event, event)
        self.assertEqual(len(created), 1)
        self.assertEqual(created[0].calls.count(p.OPEN_SESSION), 1)
        self.request(backend, p.END_ACTION, 9)
        self.assertTrue(created[0].closed)

    def retain(self):
        backend, created = self.make([p.RETRY], retain_retries=True)
        self.request(backend, p.OPEN_SESSION, 1, 0)
        self.request(backend, p.BEGIN_VERIFY, 2, payload=bytearray(b'x' * p.TEMPLATE_MIN))
        self.request(backend, p.STEP, 3)
        self.request(backend, p.END_ACTION, 4)
        return backend, created

    def test_retained_gap_cannot_verify_without_a_new_template(self):
        backend, created = self.retain()
        with self.assertRaises(OSError) as error:
            self.request(backend, p.STEP, 5)
        self.assertEqual(error.exception.errno, errno.EINVAL)
        self.assertEqual(created[0].calls, [p.OPEN_SESSION, p.BEGIN_VERIFY, p.STEP, p.END_ACTION])

    def test_retained_retry_can_be_explicitly_closed_once(self):
        backend, created = self.retain()
        reply = self.request(backend, p.CLOSE_SESSION, 5)
        self.assertEqual((reply.event, reply.flags), (p.CLOSED, 0))
        self.assertTrue(created[0].closed)
        self.assertEqual(created[0].close_calls, 1)
        self.assertFalse(backend.retry_reader)

    def test_enrollment_cannot_inherit_a_retained_verification_worker(self):
        backend, created = self.retain()
        self.request(backend, p.BEGIN_ENROLL, 5)
        self.assertTrue(created[0].closed)
        self.assertEqual(len(created), 2)
        self.assertEqual(created[1].calls, [p.OPEN_SESSION, p.BEGIN_ENROLL])

    def test_unexpected_retention_after_another_event_is_an_error(self):
        for action, event in [(p.BEGIN_VERIFY, p.WAIT_FINGER), (p.BEGIN_VERIFY, p.MATCH),
                              (p.BEGIN_VERIFY, p.NO_MATCH), (p.BEGIN_ENROLL, p.RETRY)]:
            with self.subTest(action=action, event=event):
                backend, created = self.make([event])
                self.request(backend, p.OPEN_SESSION, 1, 0)
                self.request(backend, action, 2,
                             payload=bytearray(b'x' * p.TEMPLATE_MIN) if action == p.BEGIN_VERIFY else None)
                self.request(backend, p.STEP, 3)
                forged = p.Reply(p.END_ACTION, 4, 99, event=p.CLOSED, flags=p.RETRY_SESSION_RETAINED)
                with patch.object(created[0], 'request', return_value=forged):
                    with self.assertRaises(OSError) as error:
                        self.request(backend, p.END_ACTION, 4)
                self.assertEqual(error.exception.errno, errno.EPROTO)
                self.assertTrue(created[0].closed)

    def test_disconnected_next_action_cleans_a_retained_worker(self):
        backend, created = self.retain()
        connection = MemorySocket()
        request = p.Request(p.BEGIN_VERIFY, 5, 777, bytearray(b'x' * p.TEMPLATE_MIN))
        p.send_request(connection, request)
        connection.incoming, connection.sent = connection.sent, bytearray()
        with patch('engine_backend.connection_owner', return_value=self.owner), \
                patch('engine_backend.peer_disconnected', return_value=True):
            backend.serve_one(connection)
        reply = p.read_reply(MemorySocket(connection.sent), request)
        self.assertEqual(reply.status, errno.ECANCELED)
        self.assertEqual(reply.event, 0)
        self.assertTrue(created[0].closed)
        self.assertEqual(created[0].close_calls, 1)
        self.assertFalse(backend.retry_reader)

    def test_pending_open_cleanup_accepts_zero_only_for_same_owner(self):
        backend, created = self.make()
        with self.assertRaises(OSError):
            backend.process(p.Request(p.OPEN_SESSION, 1), self.owner, cancelled=lambda: True)
        self.assertEqual(backend.phase, 'failed')
        with self.assertRaises(OSError):
            backend.process(p.Request(p.CLOSE_SESSION, 2), (100, 5001))
        reply = self.request(backend, p.CLOSE_SESSION, 2, 0)
        self.assertEqual((reply.event, reply.session_id), (p.CLOSED, 0))
        self.assertTrue(created[0].closed)

    def test_zero_close_cannot_cancel_a_fully_open_claim(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        with self.assertRaises(OSError):
            self.request(backend, p.CLOSE_SESSION, 2, 0)
        self.assertFalse(created[0].closed)

    def test_verify_match_and_no_match_are_exact_worker_events(self):
        for event in (p.MATCH, p.NO_MATCH):
            backend, created = self.make([event])
            self.request(backend, p.OPEN_SESSION, 1, 0)
            self.request(backend, p.BEGIN_VERIFY, 2, payload=bytearray(b'x' * p.TEMPLATE_MIN))
            reply = self.request(backend, p.STEP, 3)
            self.assertEqual(reply.event, event)
            self.assertEqual(backend.phase, 'finished')
            with self.assertRaises(OSError):
                self.request(backend, p.STEP, 4)

    def test_wrong_action_result_cannot_be_reported_as_success(self):
        backend, created = self.make([p.MATCH])
        self.request(backend, p.OPEN_SESSION, 1, 0)
        self.request(backend, p.BEGIN_ENROLL, 2)
        with self.assertRaises(OSError):
            self.request(backend, p.STEP, 3)

    def test_owner_death_or_pid_reuse_closes_without_claiming_new_process(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        backend.identity_reader = lambda pid: (100, 5001)
        backend.idle_cleanup()
        self.assertTrue(created[0].closed)
        self.assertIsNone(backend.owner)

    def test_idle_expiry_keeps_owner_for_explicit_cleanup(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        backend.clock = lambda: backend.last_activity + 31
        backend.idle_cleanup()
        self.assertTrue(created[0].closed)
        self.assertEqual(backend.owner, self.owner)
        self.assertEqual(backend.phase, 'failed')

    def test_competing_socket_error_never_closes_owner(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        outbound = MemorySocket()
        p.send_request(outbound, p.Request(p.CLOSE_SESSION, 2, 777))
        connection = MemorySocket(outbound.sent)
        with patch('engine_backend.connection_owner', return_value=(101, 1)), \
                patch('engine_backend.peer_disconnected', return_value=False):
            backend.serve_one(connection)
        self.assertFalse(created[0].closed)
        result = p.read_reply(MemorySocket(connection.sent), p.Request(p.CLOSE_SESSION, 2, 777))
        self.assertEqual(result.status, errno.EBUSY)

    def test_served_template_buffer_is_erased_after_delivery(self):
        backend, created = self.make([p.ENROLL_COMPLETE])
        self.request(backend, p.OPEN_SESSION, 1, 0)
        self.request(backend, p.BEGIN_ENROLL, 2)
        result = p.Reply(p.STEP, 1, 99, event=p.ENROLL_COMPLETE,
                         blob=bytearray(b'x' * p.TEMPLATE_MIN))
        created[0].request = MagicMock(return_value=result)
        outbound = MemorySocket()
        p.send_request(outbound, p.Request(p.STEP, 3, 777))
        connection = MemorySocket(outbound.sent)
        with patch('engine_backend.connection_owner', return_value=self.owner), \
                patch('engine_backend.peer_disconnected', return_value=False):
            backend.serve_one(connection)
        self.assertFalse(any(result.blob))
        decoded = p.read_reply(MemorySocket(connection.sent), p.Request(p.STEP, 3, 777))
        self.assertEqual(decoded.event, p.ENROLL_COMPLETE)

    def test_close_failure_survives_until_explicit_acknowledgement(self):
        backend, created = self.make()
        self.request(backend, p.OPEN_SESSION, 1, 0)
        created[0].close = MagicMock(side_effect=OSError(errno.EIO, 'synthetic close failure'))
        with self.assertRaises(OSError):
            self.request(backend, p.CLOSE_SESSION, 2)
        self.assertIsNotNone(backend.failed_close)
        backend.acknowledge_close()
        self.assertIsNone(backend.failed_close)

    def test_process_stat_name_with_parentheses_does_not_shift_start_time(self):
        tail = ['S'] + ['0'] * 18 + ['123456'] + ['0'] * 3
        with patch('engine_backend.Path.read_text', return_value='123 (name (with spaces)) ' + ' '.join(tail)):
            self.assertEqual(process_identity(123), (123, 123456))

    def test_check_only_verifies_manifest_and_never_opens_hardware(self):
        verify = MagicMock(return_value={})
        with patch.dict('sys.modules', {'engine_build': types.SimpleNamespace(verify_build=verify)}), \
                patch('engine_backend.check_machine') as machine, \
                patch('engine_backend.listen') as listener:
            main(['--check'])
        verify.assert_called_once()
        machine.assert_not_called()
        listener.assert_not_called()


if __name__ == '__main__':
    unittest.main()
