"""Bounded original-Engine protocol shared by the candidate service and worker.

The ABI matches engine_v2_protocol.h. Payloads are owned mutable buffers and
must be erased by the receiver after use. No image or feature payload exists.
"""
from dataclasses import dataclass, field
import errno
import struct

VERSION = 2
HEADER = struct.Struct('<4sHHIIQiI')
METADATA = struct.Struct('<8I')
TEMPLATE_MAX = 4 * 1024 * 1024
TEMPLATE_MIN = 0x255
PAYLOAD_MAX = TEMPLATE_MAX + METADATA.size
PROFILE = 12
TARGET_COUNT = 20
SOCKET_PATH = '/run/gxfp51b7-engine/reader.sock'
DESCRIBE, OPEN_SESSION, BEGIN_ENROLL, BEGIN_VERIFY, STEP, END_ACTION, CLOSE_SESSION = range(1, 8)
READY, WAIT_FINGER, WAIT_REMOVE, ENROLL_ACCEPTED, RETRY, ENROLL_COMPLETE, MATCH, NO_MATCH, CLOSED = range(1, 10)
ADAPTIVE_UPDATE_DISCARDED, REQUIRES_EMPTY_START, RETRY_SESSION_RETAINED = 1, 2, 4
OPERATIONS = frozenset(range(1, 8))
EVENTS = frozenset(range(1, 10))


def erase(value):
    if isinstance(value, bytearray):
        value[:] = b'\0' * len(value)


def read_exact(connection, size):
    if type(size) is not int or not 0 <= size <= PAYLOAD_MAX:
        raise ValueError('Original Engine payload length is out of bounds')
    data = bytearray(size)
    position = 0
    try:
        while position < size:
            count = connection.recv_into(memoryview(data)[position:])
            if count <= 0:
                raise EOFError('Original Engine channel closed')
            position += count
        return data
    except BaseException:
        erase(data)
        raise


@dataclass
class Request:
    operation: int
    request_id: int
    session_id: int = 0
    payload: bytearray = field(default_factory=bytearray)

    def close(self):
        erase(self.payload)


@dataclass
class Reply:
    operation: int
    request_id: int
    session_id: int
    status: int = 0
    event: int = READY
    used: int = 0
    target: int = 0
    progress: int = 0
    hint: int = 0
    quality: int = 0
    coverage: int = 0
    flags: int = 0
    blob: bytearray = field(default_factory=bytearray)

    def close(self):
        erase(self.blob)


def _identity(operation, request_id, session_id):
    if (type(operation) is not int or operation not in OPERATIONS or
            type(request_id) is not int or not 0 < request_id < 2**32 or
            type(session_id) is not int or not 0 <= session_id < 2**64):
        raise ValueError('Invalid original Engine message identity')


def validate_request(request):
    _identity(request.operation, request.request_id, request.session_id)
    if not isinstance(request.payload, bytearray):
        raise ValueError('Original Engine request payload must be mutable')
    if request.operation in (DESCRIBE, OPEN_SESSION):
        if request.session_id:
            raise ValueError('Session creation must not reuse an identity')
    elif not request.session_id and request.operation != CLOSE_SESSION:
        raise ValueError('Original Engine request requires a session')
    if request.operation == BEGIN_VERIFY:
        if not TEMPLATE_MIN <= len(request.payload) <= TEMPLATE_MAX:
            raise ValueError('Sealed template is outside the resource bound')
    elif request.payload:
        raise ValueError('Unexpected original Engine request payload')


def read_request(connection):
    header = read_exact(connection, HEADER.size)
    magic, version, operation, size, sequence, session, status, event = HEADER.unpack(header)
    if magic != b'GXOE' or version != VERSION or status or event:
        raise ValueError('Invalid original Engine request header')
    _identity(operation, sequence, session)
    # Validate length before allocation or waiting for a malicious body.
    if ((operation == BEGIN_VERIFY and not TEMPLATE_MIN <= size <= TEMPLATE_MAX) or
            (operation != BEGIN_VERIFY and size)):
        raise ValueError('Unexpected original Engine request size')
    request = Request(operation, sequence, session, read_exact(connection, size))
    try:
        validate_request(request)
        return request
    except BaseException:
        request.close()
        raise


def send_request(connection, request):
    validate_request(request)
    connection.sendall(HEADER.pack(b'GXOE', VERSION, request.operation, len(request.payload),
                                   request.request_id, request.session_id, 0, 0))
    if request.payload:
        connection.sendall(request.payload)


def validate_reply(reply):
    _identity(reply.operation, reply.request_id, reply.session_id)
    if type(reply.status) is not int or not 0 <= reply.status <= 4095:
        raise ValueError('Invalid original Engine response errno')
    if not isinstance(reply.blob, bytearray):
        raise ValueError('Original Engine response blob must be mutable')
    values = (reply.used, reply.target, reply.progress, reply.hint, reply.quality,
              reply.coverage, reply.flags)
    if any(type(value) is not int or not 0 <= value < 2**32 for value in values):
        raise ValueError('Invalid original Engine numeric metadata')
    if reply.flags & ~(ADAPTIVE_UPDATE_DISCARDED | REQUIRES_EMPTY_START | RETRY_SESSION_RETAINED):
        raise ValueError('Unknown original Engine response flags')
    if reply.flags & RETRY_SESSION_RETAINED:
        if (reply.operation != END_ACTION or reply.status or reply.event != CLOSED or
                reply.flags != RETRY_SESSION_RETAINED or any(values[:-1]) or reply.blob):
            raise ValueError('Invalid retained verification retry acknowledgement')
    if reply.status:
        if reply.event or reply.blob or any(values):
            raise ValueError('Failed original Engine response must be empty')
    else:
        if reply.event not in EVENTS:
            raise ValueError('Unknown original Engine response event')
        allowed_events = ({CLOSED} if reply.operation in (END_ACTION, CLOSE_SESSION) else
                          EVENTS - {READY, CLOSED} if reply.operation == STEP else {READY})
        if reply.event not in allowed_events:
            raise ValueError('Original Engine event does not match its operation')
        if reply.event == ENROLL_COMPLETE:
            if not TEMPLATE_MIN <= len(reply.blob) <= TEMPLATE_MAX:
                raise ValueError('Exported sealed template is outside the resource bound')
        elif reply.blob:
            raise ValueError('Only completed enrollment may export a template')


def send_reply(connection, reply):
    validate_reply(reply)
    size = 0 if reply.status else METADATA.size + len(reply.blob)
    connection.sendall(HEADER.pack(b'GXOR', VERSION, reply.operation, size,
                                   reply.request_id, reply.session_id, reply.status, reply.event))
    if not reply.status:
        connection.sendall(METADATA.pack(reply.used, reply.target, reply.progress, reply.hint,
                                         reply.quality, reply.coverage, reply.flags, len(reply.blob)))
        if reply.blob:
            connection.sendall(reply.blob)


def read_reply(connection, request):
    header = read_exact(connection, HEADER.size)
    magic, version, operation, size, sequence, session, status, event = HEADER.unpack(header)
    if (magic != b'GXOR' or version != VERSION or operation != request.operation or
            sequence != request.request_id or not 0 <= status <= 4095 or
            (request.operation == OPEN_SESSION and not status and not session) or
            (request.operation != OPEN_SESSION and session != request.session_id)):
        raise ValueError('Original Engine response does not match its request')
    if status:
        if size or event:
            raise ValueError('Failed original Engine response must have no body')
        return Reply(operation, sequence, session, status=status, event=0)
    if not METADATA.size <= size <= PAYLOAD_MAX or event not in EVENTS:
        raise ValueError('Invalid original Engine response size or event')
    metadata = read_exact(connection, METADATA.size)
    values = METADATA.unpack(metadata)
    blob_length = values[-1]
    if size != METADATA.size + blob_length:
        raise ValueError('Original Engine response length mismatch')
    if ((event == ENROLL_COMPLETE and not TEMPLATE_MIN <= blob_length <= TEMPLATE_MAX) or
            (event != ENROLL_COMPLETE and blob_length)):
        raise ValueError('Unexpected original Engine response payload')
    reply = Reply(operation, sequence, session, 0, event, *values[:-1],
                  blob=read_exact(connection, blob_length))
    try:
        validate_reply(reply)
        return reply
    except BaseException:
        reply.close()
        raise


def error_reply(request, error, session_id=None):
    code = error.errno if isinstance(error, OSError) and error.errno else errno.EIO
    if not 0 < code <= 4095:
        code = errno.EIO
    return Reply(request.operation, request.request_id,
                 request.session_id if session_id is None else session_id,
                 status=code, event=0)
