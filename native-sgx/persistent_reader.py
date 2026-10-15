#!/usr/bin/env python3
"""Finite native Linux SGX/TLS session for controlled capture experiments.

The root parent keeps the existing transport and sealed-input privileges.
The OS-free runner has no capabilities and communicates through a private
socket. No keys, image bytes or template contents are written to disk.
"""
from array import array
import errno
import fcntl
import os
from pathlib import Path
import socket
import sys
import time

from fprint_backend import create_sealed_input, erase, numeric_status_line, WORKER_STATUS_FIELDS
from run_trial import drop_privileges, runner_arguments, reap_worker
from transport_server import serve_transport

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
MAX_FRAMES = 512
MAX_RPC_REQUESTS = 65536
SESSION_LOG_LIMIT = 2 * 1024 * 1024


def session_log():
    fd = os.memfd_create('gxfp51b7-session-status', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.ftruncate(fd, SESSION_LOG_LIMIT)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_SEAL | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        return fd
    except BaseException:
        os.close(fd)
        raise


def session_status_and_close(fd):
    """Only fixed numeric status fields leave the sealed, bounded RAM log."""
    data = bytearray(SESSION_LOG_LIMIT)
    try:
        if os.fstat(fd).st_size != SESSION_LOG_LIMIT:
            raise ValueError('Invalid session RAM log size')
        count = os.preadv(fd, [data], 0)
        status = {}
        for line in memoryview(data)[:count].tobytes().splitlines():
            status.update(numeric_status_line(line, WORKER_STATUS_FIELDS))
        return status
    finally:
        data[:] = b'\0' * len(data)
        try:
            position = 0
            while position < len(data):
                written = os.pwrite(fd, memoryview(data)[position:], position)
                if written <= 0:
                    raise OSError('Session RAM log erasure failed')
                position += written
        finally:
            os.close(fd)


class CaptureController:
    def __init__(self):
        self.command = None
        self.pending = False
        self.pixels = None
        self.frames = 0
        self.closing = False

    def request(self, command):
        if command not in (1, 2) or self.command is not None or self.pending or self.pixels is not None:
            raise RuntimeError('Invalid native session command order')
        if command == 1 and (self.closing or self.frames >= MAX_FRAMES):
            raise RuntimeError('Native session frame limit')
        self.command = command

    def next_capture(self):
        # Called at op8 and again at op6 by the shared transport. The command
        # is consumed exactly once, and accept() closes the pending capture.
        if self.pending:
            return 1
        if self.command is None:
            raise RuntimeError('Native session has no pending request')
        command, self.command = self.command, None
        self.pending = command == 1
        self.closing = command == 2
        return command

    def accept(self, decoded):
        if not self.pending or self.pixels is not None or len(decoded) != 5120 or self.frames >= MAX_FRAMES:
            raise RuntimeError('Unexpected native session image')
        if any(not 0 <= value <= 4095 for value in decoded):
            raise RuntimeError('Invalid native session pixel range')
        self.pixels = array('H', decoded)
        self.pending = False
        self.frames += 1

    def take(self):
        if self.pixels is None:
            raise RuntimeError('Native session produced no image')
        output, self.pixels = self.pixels, None
        return output

    def close(self):
        erase(self.pixels)
        self.pixels = None
        self.command = None
        self.pending = False
        self.closing = True


class PersistentReader:
    def __init__(self, report=None, factory_calibration=False):
        if type(factory_calibration) is not bool:
            raise ValueError('Invalid factory calibration mode')
        self.factory_calibration = factory_calibration
        self.last_factory_status = {}
        self.report = report or (lambda value: print(value, flush=True))
        self.controller = CaptureController()
        self.bridge = self.parent = None
        self.child = None
        self.pid = -1
        self.log_fd = self.epc_fd = self.sealed_fd = -1
        self.requests = 0
        self.started = time.monotonic()
        self.closed = False
        self.last_exit_code = None
        self.last_worker_status = {}

    def start(self):
        if self.parent is not None or self.closed:
            raise RuntimeError('Native session already started or closed')
        sys.path.insert(0, str(PROJECT / 'sgx-vm'))
        from tls_bridge import TlsBridge
        try:
            self.sealed_fd = create_sealed_input(report=self.report)
            self.epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
            os.set_inheritable(self.sealed_fd, True)
            os.set_inheritable(self.epc_fd, True)
            self.log_fd = session_log()
            options = dict(allow_capture=True, native_session=self.controller)
            if self.factory_calibration:
                options['factory_calibration'] = True
            self.bridge = TlsBridge(self.report, **options)
            self.parent, self.child = socket.socketpair()
            self.child.set_inheritable(True)
            args = runner_arguments(self.epc_fd, self.sealed_fd, self.child.fileno(), True)
            args[0] = str(HERE / 'persistent_runner')
            args[8] = '2'
            self.pid = os.fork()
            if self.pid == 0:
                try:
                    self.parent.close()
                    os.dup2(self.log_fd, 1)
                    os.dup2(self.log_fd, 2)
                    drop_privileges()
                    os.execve(args[0], args, {'PATH': '/usr/bin'})
                except BaseException:
                    os._exit(1)
            self.child.close()
            self.child = None
            for name in ('epc_fd', 'sealed_fd'):
                os.close(getattr(self, name))
                setattr(self, name, -1)
        except BaseException:
            self.close()
            raise

    def capture(self):
        if self.parent is None:
            self.start()
        if self.closed or time.monotonic() - self.started > 1200:
            raise TimeoutError('Native session lifetime expired')
        started = time.monotonic()
        self.controller.request(1)
        try:
            count = serve_transport(self.parent, self.bridge, time.monotonic() + 45,
                                    allow_capture=True, allow_session=True, stop_after_image=True)
            self.requests += count
            if self.bridge.finished:
                raise OSError(errno.EIO, 'Native capture session finished before yielding an image')
            if self.requests > MAX_RPC_REQUESTS:
                raise RuntimeError('Native session RPC limit')
            output = self.controller.take()
            self.report('native_persistent_frame=' + str(self.controller.frames) +
                        ' authenticated=1 crc_valid=1 elapsed=' + format(time.monotonic() - started, '.3f') +
                        ' image_bytes_logged=0')
            return output
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.closed:
            return self.last_exit_code
        self.closed = True
        result = -1
        cleanup_complete = False
        try:
            try:
                if self.parent is not None and self.pid > 0:
                    # Complete the ordinary op8=2, op5 and enclave-TLS-exit path.
                    # If an earlier frame failed, closing RPC still bounds the
                    # worker without a signal across its UID change.
                    self.controller.close()
                    self.controller.request(2)
                    try:
                        serve_transport(self.parent, self.bridge, time.monotonic() + 10,
                                        allow_capture=True, allow_session=True)
                    except (OSError, EOFError, RuntimeError, ValueError):
                        self.report('native_persistent_finish_rpc_failed=1')
            finally:
                try:
                    parent, child = self.parent, self.child
                    self.parent = self.child = None
                    try:
                        if parent is not None: parent.close()
                    finally:
                        if child is not None: child.close()
                finally:
                    try:
                        if self.pid > 0:
                            result = reap_worker(self.pid, time.monotonic() + 35)
                            self.pid = -1
                    finally:
                        try:
                            if self.bridge is not None:
                                try:
                                    self.bridge.close()
                                finally:
                                    self.last_factory_status = dict(getattr(self.bridge, 'factory_status', {}))
                                    self.bridge = None
                        finally:
                            try:
                                self.controller.close()
                                if self.log_fd >= 0:
                                    fd, self.log_fd = self.log_fd, -1
                                    # This helper owns and closes fd even when
                                    # parsing or RAM erasure fails.
                                    self.last_worker_status = session_status_and_close(fd)
                            finally:
                                epc, sealed = self.epc_fd, self.sealed_fd
                                self.epc_fd = self.sealed_fd = -1
                                try:
                                    if epc >= 0: os.close(epc)
                                finally:
                                    if sealed >= 0: os.close(sealed)
            cleanup_complete = True
            return result
        finally:
            # A zero worker exit alone cannot hide a later unload/log/FD
            # failure when the caller invokes close a second time.
            self.last_exit_code = result if cleanup_complete else (result or 1)
            self.report('native_persistent_worker_exit=' + str(self.last_exit_code) +
                        ' sensor_transport_closed=' + str(int(cleanup_complete)) + ' ram_only=1')
