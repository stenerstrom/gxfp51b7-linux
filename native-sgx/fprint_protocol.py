"""Small, bounded AF_UNIX protocol used by the real ChicagoHS libfprint driver.

No executable commands, filenames, user names or authentication decisions
cross this boundary. Only real capture, cached background and device status.
"""
import errno
from pathlib import Path
import socket
import struct

REQUEST = struct.Struct('<4sIII')
REPLY = struct.Struct('<4sIIIII')
WIDTH, HEIGHT = 80, 64
IMAGE_BYTES = WIDTH * HEIGHT * 2
DESCRIBE, CAPTURE, BACKGROUND, END_SESSION = 0, 1, 2, 3


def error_metadata(error, prefix='libfprint_backend_request_error='):
    """Return only exception type, errno and final code location."""
    origin = error.__traceback__
    while origin is not None and origin.tb_next is not None:
        origin = origin.tb_next
    location = 'unknown'
    if origin is not None:
        code = origin.tb_frame.f_code
        location = (Path(code.co_filename).name + ':' + str(origin.tb_lineno) +
                    ':' + code.co_name)
    number = error.errno if isinstance(error, OSError) and error.errno else 0
    return prefix + type(error).__name__ + ' errno=' + str(number) + ' origin=' + location


def root_peer(connection):
    pid, uid, gid = struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    return pid > 0 and uid == 0


def read_operation(connection):
    data = bytearray(REQUEST.size)
    position = 0
    while position < len(data):
        received = connection.recv_into(memoryview(data)[position:])
        if not received:
            raise EOFError('Truncated libfprint request')
        position += received
    magic, version, operation, length = REQUEST.unpack(data)
    if magic != b'GXFP' or version != 1 or length != 0 or operation not in (DESCRIBE, CAPTURE, BACKGROUND, END_SESSION):
        raise ValueError('Invalid libfprint request')
    return operation


def send_reply(connection, status=0, pixels=None):
    if not isinstance(status, int) or not 0 <= status <= 4095:
        raise ValueError('Invalid response status')
    if status and pixels is not None:
        raise ValueError('Failed response must have no image')
    payload = bytearray()
    try:
        if pixels is not None:
            if len(pixels) != WIDTH * HEIGHT or any(not 0 <= value <= 4095 for value in pixels):
                raise ValueError('Invalid decoded image')
            # Explicit little endian, no immutable pixel copy left by tobytes().
            payload = bytearray(IMAGE_BYTES)
            for index, value in enumerate(pixels):
                payload[2 * index] = value & 255
                payload[2 * index + 1] = value >> 8
        connection.sendall(REPLY.pack(b'GXFR', 1, status, WIDTH, HEIGHT, len(payload)))
        if payload:
            connection.sendall(payload)
    finally:
        payload[:] = b'\0' * len(payload)


def send_error(connection, error):
    send_reply(connection, error.errno if isinstance(error, OSError) and error.errno else errno.EIO)
