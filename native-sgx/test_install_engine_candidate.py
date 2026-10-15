"""Synthetic release, rollback and readiness-evidence tests; no system mutations."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import check_engine_candidate as smoke
import install_engine_candidate as install


class FakeSystem:
    def __init__(self, backend='active', fprintd='inactive', fail_start=False):
        self.states = {install.BACKEND: backend, install.FPRINTD: fprintd}
        self.calls = []
        self.fail_start = fail_start

    def state(self, unit):
        return self.states[unit]

    def command(self, action, unit=None):
        self.calls.append((action, unit))
        if action == 'start' and self.fail_start:
            self.fail_start = False
            raise RuntimeError('Synthetic candidate start failed')
        if action in ('start', 'stop'):
            self.states[unit] = 'active' if action == 'start' else 'inactive'


class RolloutTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.current = self.root / 'current'
        self.current.symlink_to('releases/0123456789abcdef')
        self.release = self.root / 'releases/fedcba9876543210'
        self.release.mkdir(parents=True)
        self.unit = self.root / 'backend.service'
        self.dropin = self.root / 'fprintd.conf'
        self.originals = {self.unit: b'old backend\n', self.dropin: b'old library\n'}
        for path, data in self.originals.items():
            path.write_bytes(data)
            path.chmod(0o644)
        self.updates = {self.unit: b'candidate backend\n', self.dropin: b'candidate library\n'}

    def tearDown(self):
        self.temp.cleanup()

    def run_transaction(self, system, probe=lambda: None, unchanged=lambda: None):
        install.apply_transaction(self.current, self.release, self.updates, system, probe, unchanged,
                                  owner=os.getuid())

    def assert_restored(self, system, backend='active'):
        self.assertEqual(self.current.readlink(), Path('releases/0123456789abcdef'))
        for path, data in self.originals.items():
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)
        self.assertEqual(system.state(install.BACKEND), backend)
        self.assertEqual(system.state(install.FPRINTD), 'inactive')

    def test_success_commits_only_after_readiness_and_preservation_checks(self):
        system, sequence = FakeSystem(), []
        self.run_transaction(system, lambda: sequence.append('claim-release'),
                             lambda: sequence.append('preservation'))
        self.assertEqual(sequence, ['claim-release', 'preservation'])
        self.assertEqual(self.current.readlink(), Path('releases/fedcba9876543210'))
        for path, data in self.updates.items():
            self.assertEqual(path.read_bytes(), data)

    def test_failed_claim_release_restores_exact_previous_configuration(self):
        system = FakeSystem()
        def fail():
            raise RuntimeError('Synthetic clean-close failure')
        with self.assertRaisesRegex(RuntimeError, 'clean-close'):
            self.run_transaction(system, fail)
        self.assert_restored(system)

    def test_post_probe_storage_change_rolls_back(self):
        system = FakeSystem()
        def fail():
            raise RuntimeError('Synthetic storage metadata changed')
        with self.assertRaisesRegex(RuntimeError, 'metadata'):
            self.run_transaction(system, unchanged=fail)
        self.assert_restored(system)

    def test_candidate_start_failure_restores_old_service(self):
        system = FakeSystem(fail_start=True)
        with self.assertRaisesRegex(RuntimeError, 'start failed'):
            self.run_transaction(system)
        self.assert_restored(system)

    def test_initially_inactive_backend_remains_inactive_after_rollback(self):
        system = FakeSystem(backend='inactive', fail_start=True)
        with self.assertRaises(RuntimeError):
            self.run_transaction(system)
        self.assert_restored(system, backend='inactive')

    def test_active_user_fprintd_is_left_untouched(self):
        system = FakeSystem(fprintd='active')
        with self.assertRaisesRegex(RuntimeError, 'existing user operation'):
            self.run_transaction(system)
        self.assertEqual(system.calls, [])
        self.assertEqual(self.current.readlink(), Path('releases/0123456789abcdef'))

    def test_pam_activated_daemon_can_exit_without_any_stop_command(self):
        system = FakeSystem(fprintd='active')
        sleeps = []
        def idle_exit(seconds):
            sleeps.append(seconds)
            system.states[install.FPRINTD] = 'inactive'
        with patch.object(install, 'emit'):
            install.wait_for_fprintd_exit(system, clock=lambda: 0, sleep=idle_exit)
        self.assertEqual(sleeps, [.5])
        self.assertFalse(system.calls)
        self.assertEqual(self.current.readlink(), Path('releases/0123456789abcdef'))

    def test_busy_daemon_wait_expires_without_changing_services_or_release(self):
        system = FakeSystem(fprintd='active')
        now = [0]
        def advance(seconds):
            now[0] += seconds
        with patch.object(install, 'emit'):
            with self.assertRaisesRegex(RuntimeError, 'existing user operation'):
                install.wait_for_fprintd_exit(system, seconds=2,
                                             clock=lambda: now[0], sleep=advance)
        self.assertEqual(now[0], 2)
        self.assertFalse(system.calls)
        self.assertEqual(system.state(install.FPRINTD), 'active')
        self.assertEqual(self.current.readlink(), Path('releases/0123456789abcdef'))

    def test_new_activation_after_wait_is_still_rejected_by_the_transaction(self):
        system = FakeSystem()
        sleep = Mock()
        install.wait_for_fprintd_exit(system, sleep=sleep)
        sleep.assert_not_called()
        system.states[install.FPRINTD] = 'active'
        with self.assertRaisesRegex(RuntimeError, 'existing user operation'):
            self.run_transaction(system)
        self.assertFalse(system.calls)
        self.assertEqual(self.current.readlink(), Path('releases/0123456789abcdef'))

    def test_configuration_symlink_is_rejected_before_service_changes(self):
        self.dropin.unlink()
        self.dropin.symlink_to(self.unit)
        system = FakeSystem()
        with self.assertRaises(OSError):
            self.run_transaction(system)
        self.assertEqual(system.calls, [])

    def test_preexisting_atomic_temporary_is_not_deleted(self):
        temporary = self.unit.with_name(self.unit.name + '.engine-new-' + str(os.getpid()))
        temporary.write_bytes(b'preexisting')
        with self.assertRaises(FileExistsError):
            install.atomic_file(self.unit, b'new')
        self.assertEqual(temporary.read_bytes(), b'preexisting')
        self.assertEqual(self.unit.read_bytes(), self.originals[self.unit])

    def test_partial_configuration_failure_rolls_back_pointer_and_bytes(self):
        system = FakeSystem()
        original = install.atomic_file
        calls = 0
        def fail_second(path, data, mode=0o644):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError('Synthetic interrupted config update')
            original(path, data, mode)
        with patch.object(install, 'atomic_file', side_effect=fail_second):
            with self.assertRaisesRegex(RuntimeError, 'interrupted config'):
                self.run_transaction(system)
        self.assert_restored(system)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / 'protected-root'
        self.checked = {install.MANIFEST: b'synthetic manifest', install.EXECUTABLE: b'synthetic worker'}
        for target in install.LINKS.values():
            name = os.path.normpath('lib/' + target)
            self.checked[name] = b'synthetic library'
        self.hash = hashlib.sha256(self.checked[install.MANIFEST]).hexdigest()
        self.release = install.prepare_release(self.root, self.checked, self.hash, owner=os.getuid())

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        install.verify_release(self.release, self.checked, owner=os.getuid())

    def test_exact_release_is_reusable(self):
        self.verify()
        self.assertEqual(install.prepare_release(self.root, self.checked, self.hash, owner=os.getuid()), self.release)

    def test_modified_file_rejected(self):
        (self.release / install.EXECUTABLE).write_bytes(b'changed worker')
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_wrong_library_symlink_rejected(self):
        path = self.release / 'lib/libgusb.so.2'
        path.unlink()
        path.symlink_to('/tmp/unrelated')
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_extra_or_writable_file_rejected(self):
        path = self.release / 'extra'
        path.write_bytes(b'extra')
        with self.assertRaises(RuntimeError):
            self.verify()
        path.unlink()
        (self.release / install.EXECUTABLE).chmod(0o777)
        with self.assertRaises(RuntimeError):
            self.verify()

    def test_manifest_changed_rejected_before_copy(self):
        project = Path(self.temp.name) / 'source'
        manifest = project / install.MANIFEST
        manifest.parent.mkdir(parents=True)
        manifest.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'differs'):
            install.checked_inputs(project, 'a' * 64)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.identity = {'_PID': '123', '_UID': '0', '_BOOT_ID': 'a' * 32,
                         '_SYSTEMD_UNIT': install.BACKEND, '_SYSTEMD_INVOCATION_ID': 'b' * 32}
        self.checkpoint = dict(self.identity, __CURSOR='cursor-1', __MONOTONIC_TIMESTAMP='100', MESSAGE='ready')
        self.close = dict(self.identity, __CURSOR='cursor-2', __MONOTONIC_TIMESTAMP='101',
                          MESSAGE='engine_worker_closed=1 exit=0 frames=1 restored=1')

    def count(self, events):
        return smoke.clean_close_count(events, self.checkpoint, self.identity)

    def test_fresh_exact_clean_close_is_accepted(self):
        self.assertEqual(self.count([self.close]), 1)

    def test_missing_message_does_not_hide_or_replace_clean_close(self):
        empty = dict(self.identity, __CURSOR='cursor-empty', __MONOTONIC_TIMESTAMP='102')
        self.assertEqual(self.count([empty]), 0)
        self.assertEqual(self.count([self.close, empty]), 1)
        # A metadata-only record remains usable as a journal checkpoint, not
        # as evidence that the original worker actually restored the sensor.
        smoke.validate_record(empty, self.identity)

    def test_missing_message_still_requires_authenticated_fresh_metadata(self):
        empty = dict(self.identity, __CURSOR='cursor-empty', __MONOTONIC_TIMESTAMP='102')
        for changes in ({'_PID': '124'}, {'_UID': '1000'},
                        {'__CURSOR': 'cursor-1'}, {'__MONOTONIC_TIMESTAMP': '100'}):
            with self.subTest(changes=changes):
                with self.assertRaises(RuntimeError):
                    self.count([self.close, dict(empty, **changes)])
        with self.assertRaises(RuntimeError):
            self.count([self.close, empty, empty])

    def test_present_nontext_message_remains_rejected(self):
        for message in (None, [], [101, 110, 103], b'engine_worker_closed=1', {}, 0):
            with self.subTest(message_type=type(message).__name__):
                with self.assertRaises(RuntimeError):
                    self.count([dict(self.close, MESSAGE=message)])

    def test_journal_requests_complete_long_fields_and_counts_only_exact_close(self):
        diagnostics = dict(self.identity, __CURSOR='cursor-diagnostics',
                           __MONOTONIC_TIMESTAMP='102',
                           MESSAGE='engine_worker_diagnostics=' + json.dumps(list(range(1200))))
        self.assertGreater(len(diagnostics['MESSAGE']), 4096)
        def journal_output(arguments, **kwargs):
            self.assertIn('--all', arguments)
            self.assertIn('--after-cursor=cursor-1', arguments)
            return json.dumps(self.close) + '\n' + json.dumps(diagnostics) + '\n'
        with patch.object(smoke.subprocess, 'run', return_value=Mock(returncode=0)), \
                patch.object(smoke.subprocess, 'check_output', side_effect=journal_output):
            actual = smoke.records(self.identity, self.checkpoint['__CURSOR'])
        self.assertEqual(self.count(actual), 1)
        self.assertEqual(self.count([diagnostics]), 0)

    def test_failed_restoration_stale_duplicate_and_other_instance_are_rejected(self):
        for changes in ({'MESSAGE': 'engine_worker_closed=1 exit=0 frames=1 restored=0'},
                        {'__CURSOR': 'cursor-1'}, {'__MONOTONIC_TIMESTAMP': '100'},
                        {'_PID': '124'}, {'_UID': '1000'}, {'_SYSTEMD_INVOCATION_ID': 'c' * 32}):
            with self.subTest(changes=changes):
                with self.assertRaises(RuntimeError):
                    self.count([dict(self.close, **changes)])
        with self.assertRaises(RuntimeError):
            self.count([self.close, self.close])


class ServiceRecoveryTests(unittest.TestCase):
    def test_failed_start_waits_for_systemd_recovery_before_reporting_active(self):
        with patch.object(install.subprocess, 'run', return_value=Mock(returncode=1)), \
                patch.object(install.subprocess, 'check_output', side_effect=['failed\n', 'activating\n', 'active\n']) as states, \
                patch.object(install.time, 'monotonic', side_effect=[0, 1, 2]), \
                patch.object(install.time, 'sleep'):
            install.System().command('start', install.BACKEND)
        self.assertEqual(states.call_count, 3)

    def test_recovery_deadline_does_not_silently_report_success(self):
        with patch.object(install.subprocess, 'run', return_value=Mock(returncode=1)), \
                patch.object(install.subprocess, 'check_output', return_value='failed\n'), \
                patch.object(install.time, 'monotonic', side_effect=[0, 46]):
            with self.assertRaisesRegex(RuntimeError, 'become active'):
                install.System().command('start', install.BACKEND)


if __name__ == '__main__':
    unittest.main()
