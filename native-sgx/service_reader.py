"""Root-only operation-level factory-calibrated capture for ordinary fprintd.

Images stay in owned RAM. A finite session belongs to one daemon PID and is
closed/restored before the END acknowledgement, on errors or abandoned work.
"""
import errno
import json
import os
from pathlib import Path
import socket
import struct
import sys
import time

from fprint_backend import erase, peer_disconnected, request_error_metadata, transport_status
from fprint_protocol import (DESCRIBE, BACKGROUND, CAPTURE, END_SESSION,
                             read_operation, root_peer, send_reply, send_error)
from persistent_reader import PersistentReader, PROJECT
sys.path.insert(0, str(PROJECT / 'sgx-vm'))
from tls_bridge import FACTORY_STATUS_FIELDS

CLOSE_WORKER_FIELDS = frozenset(('trial_result', 'image_crc_valid', 'invalid_mac_callbacks',
                                'tls_final_connected_callbacks', 'tls_bridge_start_result',
                                'tls_bridge_finish_result', 'goodix_tls_exit_result',
                                'intel_le_einit_result', 'goodix_einit_result'))


def close_diagnostics(session, result):
    def numbers(status, fields):
        if type(status) is not dict: return {}
        return {key: value for key, value in status.items() if key in fields and
                type(value) is int and -(2**31) <= value < 2**32}
    return dict(exit=result if type(result) is int else None,
                sensor_restored=restored(getattr(session, 'last_factory_status', None)),
                factory=numbers(getattr(session, 'last_factory_status', None), FACTORY_STATUS_FIELDS),
                worker=numbers(getattr(session, 'last_worker_status', None), CLOSE_WORKER_FIELDS))


def report_control_errors(message):
    # The private bridge's larger RAM report may contain other diagnostics.
    # Only the fixed numeric control-failure record reaches the service log.
    for record in transport_status(message):
        if (record.get('factory_transfer_error', 0) != 0 or 'factory_read_retry_error' in record or
                record.get('factory_wait_command') is not None and record.get('error', 0) != 0 or
                'factory_irq_ack_command' in record or 'factory_ready_command' in record):
            print('libfprint_factory_transfer_diagnostics=' +
                  json.dumps(record, separators=(',', ':')), flush=True)


def restored(status):
    return (type(status) is dict and set(status) == FACTORY_STATUS_FIELDS and
            all(type(value) is int for value in status.values()) and
            all(status[k] == 0 for k in ('factory_otp_error', 'factory_snapshot_error',
                                         'factory_apply_error', 'factory_restore_error')) and
            status['factory_timing_valid'] == status['factory_snapshot_ready'] ==
            status['factory_config_crc_valid'] == 1 and
            1 <= status['factory_vendor_selection'] <= 3 and
            0 <= status['factory_prior_dac_matches'] <= 4 and
            status['factory_dac_readback_matches'] == 4 and status['factory_restored_registers'] == 7)


class PersistentServiceReader:
    def __init__(self, verbose=False, session_factory=PersistentReader):
        self.session_factory = session_factory
        self.session = None
        self.background = None
        self.owner = None
        # A cancelled capture socket cannot receive its cleanup failure. Keep
        # one owner's failed close until an explicit END reply is delivered.
        self.failed_owner = None
        self.last_activity = 0
        self.verbose = verbose

    def _warm_session(self, cancelled=lambda: False):
        if self.session is not None:
            raise OSError(errno.EBUSY, 'Operation already active')
        self.session = self.session_factory(report=report_control_errors, factory_calibration=True)
        try:
            # Identical factory profile and three discarded warmup frames to
            # the development GUI. No finger-present startup frame becomes a
            # background for the next operation.
            for _ in range(3):
                if cancelled(): raise OSError(errno.ECANCELED, 'Client disconnected')
                image = self.session.capture()
                erase(image)
                time.sleep(.7)
            self.last_activity = time.monotonic()
        except BaseException:
            self.end_session()
            raise

    def calibrate(self):
        try:
            self._warm_session()
            erase(self.background)
            self.background = self.session.capture()
        finally:
            self.end_session()
        print('libfprint_background_ready=1 ram_only=1 persistent_factory=1', flush=True)

    def end_session(self):
        session, self.session = self.session, None
        owner, self.owner = self.owner, None
        if session is None: return
        result = None
        try:
            result = session.close()
        finally:
            worker = getattr(session, 'last_worker_status', None)
            ok = (result == 0 and restored(getattr(session, 'last_factory_status', None)) and
                  type(worker) is dict and
                  all(worker.get(key) == value for key, value in
                      (('trial_result', 0), ('invalid_mac_callbacks', 0),
                       ('tls_final_connected_callbacks', 1), ('image_crc_valid', 1))))
            if not ok and owner is not None:
                self.failed_owner = owner
            print('libfprint_persistent_session_closed=1 frames=' + str(session.controller.frames) +
                  ' restored=' + str(int(ok)) + ' ram_only=1', flush=True)
            if not ok:
                print('libfprint_native_close_diagnostics=' +
                      json.dumps(close_diagnostics(session, result), separators=(',', ':')), flush=True)
        if not ok: raise OSError(errno.EIO, 'Native factory session did not close cleanly')

    def idle_cleanup(self):
        if self.failed_owner is not None and not Path('/proc', str(self.failed_owner)).exists():
            self.failed_owner = None
        if self.session is not None and (time.monotonic() - self.last_activity > 30 or
                                        self.owner is not None and not Path('/proc', str(self.owner)).exists()):
            self.end_session()

    def serve_one(self, connection):
        pixels = None
        pid = operation = None
        try:
            if not root_peer(connection):
                raise PermissionError(errno.EACCES, 'Only root may use this reader')
            pid, _, _ = struct.unpack('3i', connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            connection.settimeout(45)
            operation = read_operation(connection)
            if operation == DESCRIBE:
                send_reply(connection)
                return
            owner = self.owner if self.owner is not None else self.failed_owner
            if owner is not None and owner != pid:
                raise PermissionError(errno.EBUSY, 'Another daemon owns the session')
            if operation == END_SESSION:
                self.end_session()
                if self.failed_owner == pid:
                    raise OSError(errno.EIO, 'Native factory session did not close cleanly')
                send_reply(connection)
                return
            if self.failed_owner == pid:
                raise OSError(errno.EIO, 'Acknowledge the failed close before starting an operation')
            if operation == BACKGROUND:
                if self.background is None: raise OSError(errno.ENODATA, 'Background unavailable')
                self.owner = pid
                # A libfprint retry is a new logical attempt on the same
                # claimed device. Resume its authenticated session; only a
                # real close/idle cleanup requires another warmup.
                if self.session is None:
                    self._warm_session(lambda: peer_disconnected(connection))
                pixels = self.background[:]
            elif operation == CAPTURE:
                if self.session is None: raise OSError(errno.EINVAL, 'Start an operation first')
                if peer_disconnected(connection): raise OSError(errno.ECANCELED, 'Client disconnected')
                pixels = self.session.capture()
            if peer_disconnected(connection): raise OSError(errno.ECANCELED, 'Client disconnected')
            send_reply(connection, pixels=pixels)
            self.last_activity = time.monotonic()
        except Exception as error:
            print(request_error_metadata(error), flush=True)
            # An unauthenticated or competing client cannot close the owner's
            # active session. Owner errors always restore it before replying.
            if pid is not None and (self.owner is None or self.owner == pid):
                try: self.end_session()
                except Exception as cleanup:
                    print(request_error_metadata(cleanup), flush=True)
                    error = OSError(errno.EIO, 'Cleanup failed')
            try: send_error(connection, error)
            except OSError: pass
            else:
                if operation == END_SESSION and self.failed_owner == pid:
                    self.failed_owner = None
        finally:
            erase(pixels)

    def close(self):
        try:
            self.end_session()
        finally:
            erase(self.background)
            self.background = None
            print('libfprint_backend_ram_erased=1', flush=True)
