#!/usr/bin/env python3
"""Candidate root-owned original-Engine service for ordinary fprintd.

Only typed progress, exact original decisions and opaque sealed enrollment
templates cross the socket. The original signed matcher owns biometric decisions.
"""
import argparse
import errno
import os
from pathlib import Path
import secrets
import signal
import socket
import struct
import time

import engine_v2_protocol as wire
from engine_reader import EngineReader
from fprint_backend import check_machine, listen, peer_disconnected
from fprint_protocol import error_metadata

IDLE_SECONDS = 30


def process_identity(pid):
    """PID plus kernel start ticks prevents ownership surviving PID reuse."""
    if type(pid) is not int or pid <= 0:
        raise OSError(errno.EACCES, 'Invalid original Engine peer')
    data = Path('/proc', str(pid), 'stat').read_text()
    tail = data[data.rfind(')') + 2:].split()
    if len(tail) < 20 or not tail[19].isdigit():
        raise OSError(errno.EACCES, 'Original Engine peer identity unavailable')
    return pid, int(tail[19])


def connection_owner(connection):
    pid, uid, _ = struct.unpack('3i', connection.getsockopt(
        socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
    if uid != 0:
        raise PermissionError(errno.EACCES, 'Only root may use the original Engine service')
    return process_identity(pid)


class EngineBackend:
    def __init__(self, reader_factory=EngineReader, identity_reader=process_identity,
                 clock=time.monotonic, token_factory=lambda: secrets.randbits(64)):
        self.reader_factory = reader_factory
        self.identity_reader = identity_reader
        self.clock = clock
        self.token_factory = token_factory
        self.owner = None
        self.session_id = self.last_request = 0
        self.reader = None
        self.phase = 'closed'
        self.last_activity = clock()
        self.failed_close = None
        self.last_step_event = None
        self.retry_reader = False

    def _new_reader(self, cancelled):
        if self.reader is not None:
            raise RuntimeError('Original Engine worker already exists')
        self.reader = self.reader_factory()
        result = self.reader.request(wire.OPEN_SESSION, cancelled=cancelled)
        try:
            if result.event != wire.READY:
                raise OSError(errno.EIO, 'Original Engine startup did not become ready')
        finally:
            result.close()

    def _close_reader(self):
        reader, self.reader = self.reader, None
        self.last_step_event = None
        self.retry_reader = False
        if reader is None:
            return
        try:
            reader.close()
        except BaseException:
            # Do not retain a traceback that could keep a template buffer alive.
            self.failed_close = True
            raise

    def _reply(self, request, event=wire.READY, **values):
        return wire.Reply(request.operation, request.request_id,
                          0 if request.operation == wire.DESCRIBE else self.session_id,
                          event=event, **values)

    def _forward(self, request, cancelled):
        result = self.reader.request(request.operation, payload=request.payload,
                                     cancelled=cancelled)
        result.operation = request.operation
        result.request_id = request.request_id
        result.session_id = self.session_id
        return result

    def _check_owner(self, request, owner):
        if self.owner != owner:
            raise PermissionError(errno.EBUSY, 'Another daemon owns the original Engine claim')
        zero_close = request.operation == wire.CLOSE_SESSION and request.session_id == 0
        if not zero_close and request.session_id != self.session_id:
            raise OSError(errno.ESTALE, 'Original Engine session identity changed')
        # Zero-ID close is restricted to this owner's pending/failed OPEN.
        if zero_close and self.phase not in ('opening', 'failed'):
            raise OSError(errno.ESTALE, 'Zero-ID cleanup is only valid for an incomplete open')
        if request.request_id <= self.last_request:
            raise OSError(errno.EPROTO, 'Original Engine request sequence was replayed')
        self.last_request = request.request_id

    def process(self, request, owner, cancelled=lambda: False):
        wire.validate_request(request)
        if request.operation == wire.DESCRIBE:
            return self._reply(request, target=wire.TARGET_COUNT, quality=wire.PROFILE,
                               coverage=wire.TEMPLATE_MAX,
                               flags=wire.ADAPTIVE_UPDATE_DISCARDED | wire.REQUIRES_EMPTY_START)
        if request.operation == wire.OPEN_SESSION:
            if self.owner is not None:
                raise OSError(errno.EBUSY, 'Original Engine device is already claimed')
            self.owner = owner
            self.session_id = self.token_factory()
            if not 0 < self.session_id < 2**64:
                self.session_id = 1
            self.last_request = request.request_id
            self.phase = 'opening'
            try:
                self._new_reader(cancelled)
                if cancelled():
                    raise OSError(errno.ECANCELED, 'Original Engine open was cancelled')
                self.phase = 'idle'
                self.last_activity = self.clock()
                return self._reply(request, flags=wire.REQUIRES_EMPTY_START)
            except BaseException:
                self.phase = 'failed'
                raise
        self._check_owner(request, owner)
        if request.operation == wire.CLOSE_SESSION:
            token = request.session_id
            try:
                self._close_reader()
                if self.failed_close is not None:
                    raise OSError(errno.EIO, 'Original Engine cleanup previously failed')
                reply = self._reply(request, wire.CLOSED)
                # A zero-ID cleanup reply echoes zero, as required by framing.
                reply.session_id = token
                return reply
            finally:
                self.phase = 'closed'
        if self.failed_close is not None or self.phase in ('closed', 'opening', 'failed'):
            raise OSError(errno.EIO, 'Original Engine claim requires cleanup')
        if request.operation in (wire.BEGIN_ENROLL, wire.BEGIN_VERIFY):
            if self.phase != 'idle':
                raise OSError(errno.EBUSY, 'Original Engine action already active')
            # A retained worker is justified only for another verification
            # acquisition. Enrollment and completed decisions use fresh state.
            if self.retry_reader and request.operation != wire.BEGIN_VERIFY:
                self._close_reader()
            if self.reader is None:
                self._new_reader(cancelled)
            reply = self._forward(request, cancelled)
            self.phase = 'enroll' if request.operation == wire.BEGIN_ENROLL else 'verify'
            self.last_step_event = None
            self.retry_reader = False
        elif request.operation == wire.STEP:
            if self.phase not in ('enroll', 'verify') or self.reader is None:
                raise OSError(errno.EINVAL, 'Original Engine action is not active')
            reply = self._forward(request, cancelled)
            self.last_step_event = reply.event
            if reply.event in (wire.ENROLL_COMPLETE, wire.MATCH, wire.NO_MATCH):
                if ((self.phase == 'enroll') != (reply.event == wire.ENROLL_COMPLETE)):
                    reply.close()
                    raise OSError(errno.EPROTO, 'Original Engine returned the wrong action result')
                self.phase = 'finished'
        elif request.operation == wire.END_ACTION:
            if self.reader is not None:
                reply = self._forward(request, cancelled)
                retained = bool(reply.flags & wire.RETRY_SESSION_RETAINED)
                if retained and (self.phase != 'verify' or self.last_step_event != wire.RETRY or
                                 self.reader.closed):
                    reply.close()
                    self._close_reader()
                    raise OSError(errno.EPROTO, 'Unexpected retained verification retry')
                if retained:
                    self.retry_reader = True
                else:
                    self._close_reader()
            else:
                reply = self._reply(request, wire.CLOSED)
            self.phase = 'idle'
            self.last_step_event = None
        else:
            raise OSError(errno.EINVAL, 'Unexpected original Engine operation')
        self.last_activity = self.clock()
        return reply

    def acknowledge_close(self):
        """Forget ownership only after its explicit cleanup reply was delivered."""
        self.owner = None
        self.session_id = self.last_request = 0
        self.phase = 'closed'
        self.failed_close = None
        self.last_step_event = None
        self.retry_reader = False

    def serve_one(self, connection):
        owner = request = reply = None
        try:
            owner = connection_owner(connection)
            connection.settimeout(5)
            request = wire.read_request(connection)
            reply = self.process(request, owner, lambda: peer_disconnected(connection))
            if peer_disconnected(connection):
                raise OSError(errno.ECANCELED, 'Original Engine client disconnected')
            connection.settimeout(5)
            wire.send_reply(connection, reply)
            if request.operation == wire.CLOSE_SESSION:
                self.acknowledge_close()
        except Exception as error:
            print(error_metadata(error, 'engine_backend_request_error='), flush=True)
            if owner is not None and owner == self.owner:
                try:
                    self._close_reader()
                except Exception as cleanup:
                    print(error_metadata(cleanup, 'engine_backend_cleanup_error='), flush=True)
                    error = OSError(errno.EIO, 'Original Engine cleanup failed')
                self.phase = 'failed'
            if request is not None:
                try:
                    wire.send_reply(connection, wire.error_reply(request, error))
                except OSError:
                    pass
                else:
                    if request.operation == wire.CLOSE_SESSION and owner == self.owner:
                        self.acknowledge_close()
        finally:
            if reply is not None:
                reply.close()
            if request is not None:
                request.close()

    def idle_cleanup(self):
        if self.owner is None:
            return
        try:
            alive = self.identity_reader(self.owner[0]) == self.owner
        except (OSError, ValueError):
            alive = False
        if not alive or self.clock() - self.last_activity > IDLE_SECONDS:
            try:
                self._close_reader()
            finally:
                if not alive:
                    self.acknowledge_close()
                else:
                    self.phase = 'failed'

    def close(self):
        try:
            self._close_reader()
        finally:
            self.acknowledge_close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Validate the candidate build without opening hardware.')
    parser.add_argument('--socket', type=Path, default=Path(wire.SOCKET_PATH))
    args = parser.parse_args(argv)
    if args.socket != Path(wire.SOCKET_PATH):
        parser.error('Use the dedicated original Engine service endpoint')
    from engine_build import verify_build
    verify_build()
    if args.check:
        print('engine_candidate_build_verified=1 hardware_used=0 adaptive_update_persisted=0')
        return
    check_machine()
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)
    backend = EngineBackend()
    try:
        listen(backend, args.socket, lifetime=0)
    except KeyboardInterrupt:
        pass
    finally:
        backend.close()


if __name__ == '__main__':
    main()
