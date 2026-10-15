"""Synthetic framing, bounds, semantic and erasure tests for the candidate ABI."""
import errno
from pathlib import Path
import struct
import unittest

import engine_v2_protocol as p


class MemorySocket:
    def __init__(self, incoming=b'', chunk=4096):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.position = 0
        self.chunk = chunk
        self.timeout = None
        self.closed = False

    def recv_into(self, destination):
        count = min(len(destination), len(self.incoming) - self.position, self.chunk)
        destination[:count] = self.incoming[self.position:self.position + count]
        self.position += count
        return count

    def sendall(self, data):
        self.sent.extend(data)

    def settimeout(self, value):
        self.timeout = value

    def close(self):
        self.closed = True


def encoded_reply(reply):
    connection = MemorySocket()
    p.send_reply(connection, reply)
    return connection.sent


class ProtocolTests(unittest.TestCase):
    def test_header_layout_matches_c_offsets(self):
        self.assertEqual(p.HEADER.size, 32)
        self.assertEqual(p.METADATA.size, 32)
        header = p.HEADER.pack(b'GXOE', 2, p.STEP, 0, 4, 0x1122334455667788, 0, 0)
        self.assertEqual(header[16:24], bytes.fromhex('8877665544332211'))
        source = Path(__file__).with_name('engine_v2_protocol.h').read_text()
        self.assertIn('#define GXOE_TEMPLATE_MIN 0x255U', source)
        self.assertIn('#define GXOE_TEMPLATE_MAX (4U * 1024U * 1024U)', source)

    def test_mutable_sealed_request_roundtrip_and_erasure(self):
        request = p.Request(p.BEGIN_VERIFY, 2, 123, bytearray(b'a' * p.TEMPLATE_MIN))
        connection = MemorySocket()
        p.send_request(connection, request)
        decoded = p.read_request(MemorySocket(connection.sent, chunk=7))
        self.assertEqual(decoded, request)
        data = decoded.payload
        decoded.close()
        self.assertFalse(any(data))
        request.close()

    def test_completed_template_reply_roundtrip_and_erasure(self):
        request = p.Request(p.STEP, 7, 123)
        reply = p.Reply(p.STEP, 7, 123, event=p.ENROLL_COMPLETE, used=12, target=20,
                        blob=bytearray(b'x' * p.TEMPLATE_MIN))
        decoded = p.read_reply(MemorySocket(encoded_reply(reply), chunk=3), request)
        self.assertEqual(decoded, reply)
        blob = decoded.blob
        decoded.close()
        self.assertFalse(any(blob))

    def test_error_reply_has_no_metadata(self):
        request = p.Request(p.STEP, 2, 1)
        reply = p.error_reply(request, OSError(errno.EBUSY, 'synthetic'))
        encoded = encoded_reply(reply)
        self.assertEqual(len(encoded), 32)
        self.assertEqual(p.read_reply(MemorySocket(encoded), request).status, errno.EBUSY)

    def test_request_bounds_checked_before_body(self):
        for operation, length in ((p.BEGIN_VERIFY, p.TEMPLATE_MIN - 1),
                                  (p.BEGIN_VERIFY, p.TEMPLATE_MAX + 1), (p.STEP, 1)):
            with self.subTest(operation=operation, length=length):
                connection = MemorySocket(p.HEADER.pack(b'GXOE', 2, operation, length, 1, 1, 0, 0))
                with self.assertRaises(ValueError):
                    p.read_request(connection)
                self.assertEqual(connection.position, 32)

    def test_bad_headers_and_truncation_fail(self):
        for magic, version, operation, sequence, status, event in (
                (b'WRNG', 2, p.STEP, 1, 0, 0), (b'GXOE', 1, p.STEP, 1, 0, 0),
                (b'GXOE', 2, 77, 1, 0, 0), (b'GXOE', 2, p.STEP, 0, 0, 0),
                (b'GXOE', 2, p.STEP, 1, 1, 0), (b'GXOE', 2, p.STEP, 1, 0, 1)):
            with self.subTest(magic=magic, version=version, operation=operation, sequence=sequence):
                with self.assertRaises(ValueError):
                    p.read_request(MemorySocket(p.HEADER.pack(magic, version, operation, 0,
                                                             sequence, 1, status, event)))
        for length in (0, 1, 31):
            with self.assertRaises(EOFError):
                p.read_request(MemorySocket(b'\0' * length))

    def test_unexpected_reply_identity_and_template_rejected(self):
        request = p.Request(p.STEP, 2, 1)
        for operation, sequence, session in ((p.BEGIN_ENROLL, 2, 1), (p.STEP, 3, 1), (p.STEP, 2, 2)):
            message = p.HEADER.pack(b'GXOR', 2, operation, 32, sequence, session, 0, p.WAIT_FINGER)
            with self.assertRaises(ValueError):
                p.read_reply(MemorySocket(message), request)
        metadata = p.METADATA.pack(0, 0, 0, 0, 0, 0, 0, p.TEMPLATE_MIN)
        for event in (p.MATCH, p.NO_MATCH, p.WAIT_FINGER):
            message = p.HEADER.pack(b'GXOR', 2, p.STEP, 32 + p.TEMPLATE_MIN, 2, 1, 0, event) + metadata
            with self.assertRaises(ValueError):
                p.read_reply(MemorySocket(message), request)

    def test_match_adaptation_remains_match_and_is_only_a_flag(self):
        request = p.Request(p.STEP, 2, 1)
        reply = p.Reply(p.STEP, 2, 1, event=p.MATCH, flags=p.ADAPTIVE_UPDATE_DISCARDED)
        decoded = p.read_reply(MemorySocket(encoded_reply(reply)), request)
        self.assertEqual((decoded.event, decoded.flags, decoded.blob), (p.MATCH, 1, bytearray()))

    def test_retained_retry_ack_is_empty_and_only_valid_for_end_action(self):
        request = p.Request(p.END_ACTION, 4, 1)
        reply = p.Reply(p.END_ACTION, 4, 1, event=p.CLOSED, flags=4)
        decoded = p.read_reply(MemorySocket(encoded_reply(reply)), request)
        self.assertEqual((decoded.event, decoded.flags, decoded.blob), (p.CLOSED, 4, bytearray()))
        for operation, event in [(p.CLOSE_SESSION, p.CLOSED), (p.DESCRIBE, p.READY),
                                 (p.OPEN_SESSION, p.READY), (p.STEP, p.MATCH)]:
            with self.subTest(operation=operation):
                with self.assertRaises(ValueError):
                    p.validate_reply(p.Reply(operation, 4, 0 if operation == p.DESCRIBE else 1,
                                             event=event, flags=4))
        for extra in [dict(flags=5), dict(used=1), dict(hint=10)]:
            with self.subTest(extra=extra):
                values = dict(flags=4)
                values.update(extra)
                with self.assertRaises(ValueError):
                    p.validate_reply(p.Reply(p.END_ACTION, 4, 1, event=p.CLOSED, **values))

    def test_zero_id_only_for_describe_open_or_cleanup(self):
        for operation in (p.DESCRIBE, p.OPEN_SESSION, p.CLOSE_SESSION):
            p.validate_request(p.Request(operation, 1))
        for operation in (p.BEGIN_ENROLL, p.STEP, p.END_ACTION):
            with self.assertRaises(ValueError):
                p.validate_request(p.Request(operation, 1))

    def test_reply_semantics_and_flags_are_not_unchecked(self):
        for reply in (p.Reply(p.OPEN_SESSION, 1, 2, event=p.MATCH),
                      p.Reply(p.STEP, 2, 2, event=p.CLOSED),
                      p.Reply(p.STEP, 2, 2, event=p.WAIT_FINGER, flags=4),
                      p.Reply(p.STEP, 2, 2, status=errno.EIO, event=p.RETRY),
                      p.Reply(p.STEP, 2, 2, event=p.MATCH, blob=bytearray(b'x'))):
            with self.assertRaises(ValueError):
                p.validate_reply(reply)


if __name__ == '__main__':
    unittest.main()
