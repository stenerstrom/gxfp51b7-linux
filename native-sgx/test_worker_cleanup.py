#!/usr/bin/env python3
"""Exercise worker failure cleanup with fake PIDs and no device access."""
import contextlib
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'sgx-vm'))
from run_trial import run_tls_trial


class WorkerCleanupTest(unittest.TestCase):
    def trial(self, wait_results, normal=False, over_deadline=False):
        epc = os.open('/dev/null', os.O_RDONLY)
        sealed = os.open('/dev/null', os.O_RDONLY)
        pid = 1234567
        bridge = MagicMock()
        reports = []
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch('tls_bridge.TlsBridge', return_value=bridge))
            stack.enter_context(patch('run_trial.os.fork', return_value=pid))
            wait = stack.enter_context(patch('run_trial.os.waitpid', side_effect=wait_results))
            kill = stack.enter_context(patch('run_trial.os.kill'))
            stack.enter_context(patch('run_trial.time.sleep'))
            if normal:
                stack.enter_context(patch('transport_server.serve_transport', return_value=1))
                stack.enter_context(patch('run_trial.time.monotonic', side_effect=[0, 1, 2, 3]))
                result = run_tls_trial(epc, sealed, report=reports.append)
                self.assertEqual(result, 0)
            else:
                stack.enter_context(patch('transport_server.serve_transport',
                                          side_effect=EOFError('private-value-never-log')))
                if over_deadline:
                    stack.enter_context(patch('run_trial.time.monotonic', side_effect=[0, 1, 36]))
                with self.assertRaises(RuntimeError if over_deadline else EOFError):
                    run_tls_trial(epc, sealed, report=reports.append)
                self.assertTrue(any('native_sgx_operation_error=EOFError errno=0 origin=' in r
                                    for r in reports))
                self.assertFalse(any('private-value-never-log' in r for r in reports))
        bridge.close.assert_called_once_with()
        kill.assert_not_called()
        for fd in (epc, sealed):
            with self.assertRaises(OSError):
                os.fstat(fd)
        return reports, wait, kill

    def test_reap_exited_child_without_signalling_different_uid(self):
        reports, wait, kill = self.trial([(1234567, 3 << 8)])
        kill.assert_not_called()
        wait.assert_called_once_with(1234567, os.WNOHANG)
        self.assertIn('native_sgx_worker_exit=3 aborted=1', reports)

    def test_live_child_exits_after_rpc_closure_without_signal(self):
        reports, wait, kill = self.trial([(0, 0), (1234567, 1 << 8)])
        self.assertIn('native_sgx_worker_exit=1 aborted=1', reports)
        self.assertEqual(wait.call_count, 2)
        self.assertTrue(all(call.args == (1234567, os.WNOHANG) for call in wait.call_args_list))

    def test_stuck_child_is_fatal_but_transport_and_fds_are_closed(self):
        self.trial([(0, 0)], over_deadline=True)

    def test_normal_worker_exit_and_transport_close(self):
        reports, wait, kill = self.trial([(1234567, 0)], normal=True)
        self.assertIn('native_sgx_worker_exit=0 sensor_transport_closed=1', reports)
        self.assertFalse(any('aborted=1' in report for report in reports))


if __name__ == '__main__':
    unittest.main()
