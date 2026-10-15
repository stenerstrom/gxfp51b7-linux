#!/usr/bin/env python3
"""Bounded local sensor RPC for the unprivileged native SGX runner.

The root parent alone performs the existing CAP_SYS_ADMIN transport calls.
This channel carries TLS ciphertext, status and fixed operation numbers;
it logs no wire bytes, keys or fingerprints. Module lifetime belongs to the
parent, which must call TlsBridge.close() even if its child fails.
"""
import struct
import time

REQUEST = struct.Struct('<4sB3sI')
REPLY = struct.Struct('<4siI')
MAX_REQUESTS = 4096


def read_exact(connection, length):
    output = bytearray(length)
    received = 0
    try:
        while received < length:
            count = connection.recv_into(memoryview(output)[received:])
            if not count:
                raise EOFError('Native SGX transport channel closed')
            received += count
        return output
    except BaseException:
        output[:] = b'\0' * len(output)
        raise


def serve_transport(connection, bridge, deadline, allow_capture=False,
                    allow_session=False, stop_after_image=False,
                    allow_sensor_identity=False, allow_engine_metadata=False):
    """Serve bounded operations; capture requires an explicit trial option."""
    if (allow_session or stop_after_image) and not allow_capture:
        raise ValueError('Capture must be explicitly enabled for a session')
    if stop_after_image and not allow_session:
        raise ValueError('Single image yield requires an explicit session')
    if type(allow_sensor_identity) is not bool or (allow_sensor_identity and
                                                  (not allow_capture or allow_session)):
        raise ValueError('Sensor identity requires a distinct baseline capture scope')
    _metadata_scope(allow_capture, allow_session, allow_sensor_identity, allow_engine_metadata)
    for count in range(MAX_REQUESTS):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Native SGX transport deadline')
        # The original baseline includes enclave loading and calibration.
        # Its opt-in budget also accommodates bounded factory restoration;
        # ordinary capture/session timing remains unchanged.
        operation, status = serve_transport_once(
            connection, bridge, remaining if count == 0 else
            min(remaining, 60 if allow_sensor_identity or allow_engine_metadata else 5),
            allow_capture=allow_capture, allow_session=allow_session,
            allow_sensor_identity=allow_sensor_identity,
            allow_engine_metadata=allow_engine_metadata)
        if operation == 5:
            return count + 1
        if stop_after_image and operation == 7 and status == 0:
            return count + 1
    raise RuntimeError('Native SGX transport request limit')


def _metadata_scope(allow_capture, allow_session, allow_sensor_identity, enabled):
    if type(enabled) is not bool or (enabled and
            (not allow_capture or not allow_session or allow_sensor_identity)):
        raise ValueError('Engine metadata requires its explicit persistent capture scope')


def serve_transport_once(connection, bridge, timeout, allow_capture=False,
                         allow_session=False, allow_sensor_identity=False,
                         allow_engine_metadata=False):
    """Serve one checked RPC, allowing a parent to multiplex a control socket."""
    if allow_session and not allow_capture:
        raise ValueError('Capture must be explicitly enabled for a session')
    if type(allow_sensor_identity) is not bool or (allow_sensor_identity and
                                                  (not allow_capture or allow_session)):
        raise ValueError('Sensor identity requires a distinct baseline capture scope')
    _metadata_scope(allow_capture, allow_session, allow_sensor_identity, allow_engine_metadata)
    if not 0 < timeout <= 1200:
        raise ValueError('Invalid native SGX RPC timeout')
    connection.settimeout(timeout)
    header = read_exact(connection, REQUEST.size)
    magic, operation, reserved, length = REQUEST.unpack(header)
    if magic != b'GXTL' or reserved != b'\0' * 3:
        raise ValueError('Invalid native SGX transport request')
    valid = (operation in (1, 4, 5) and length == 0 or
             operation == 2 and 5 <= length <= 4092 or
             operation == 3 and length == 4 or
             allow_capture and operation == 6 and length == 0 or
             allow_capture and operation == 7 and length == 10564 or
             (allow_session or allow_sensor_identity) and operation == 8 and length == 0 or
             allow_engine_metadata and operation == 9 and length == 0)
    if not valid:
        raise ValueError('Native SGX transport operation out of bounds')
    payload = read_exact(connection, length)
    reply = None
    try:
        status, reply = bridge.call(operation, payload)
        if type(status) is not int or not 0 <= status <= 4095:
            raise ValueError('Invalid sensor transport errno')
        if allow_sensor_identity and operation == 8:
            if status == 0 and (not isinstance(reply, bytearray) or len(reply) != 16):
                raise ValueError('Sensor identity reply must contain exactly 16 mutable bytes')
            if status != 0 and reply:
                raise ValueError('Failed sensor identity reply must be empty')
        if allow_engine_metadata and operation == 9:
            if status == 0:
                if (not isinstance(reply, bytearray) or len(reply) != 24 or
                        struct.unpack_from('<HH', reply) != (1, 24) or reply[23] != 1):
                    raise ValueError('Invalid retained original Engine sensor metadata')
            elif reply:
                raise ValueError('Failed Engine metadata reply must be empty')
        if not isinstance(reply, (bytes, bytearray)) or len(reply) > 1028:
            raise ValueError('Oversized or invalid sensor transport reply')
        connection.sendall(REPLY.pack(b'GXTR', status, len(reply)))
        if reply:
            connection.sendall(reply)
    finally:
        payload[:] = b'\0' * len(payload)
        if (allow_sensor_identity and operation == 8 or
                allow_engine_metadata and operation == 9) and isinstance(reply, bytearray):
            reply[:] = b'\0' * len(reply)
    return operation, status
