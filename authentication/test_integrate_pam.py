"""Validate scoped rendering and real Linux-PAM jump/failure semantics."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import integrate_pam as integration

HERE = Path(__file__).resolve().parent


class PamControlTests(unittest.TestCase):
    def run_stack(self, closed=False, finger='success', password='auth_err',
                  preauth='success', account='success'):
        block = integration.fingerprint_block('auth required pam_debug.so auth=' + preauth)
        block = block.replace('pam_exec.so quiet type=auth /usr/bin/omarchy-hw-laptop-closed',
                              'pam_debug.so auth=' + ('success' if closed else 'auth_err'))
        block = block.replace(integration.MODULE, 'pam_debug.so auth=' + finger)
        block = block.replace('pam_faillock.so authsucc', 'pam_debug.so auth=success')
        config = '#%PAM-1.0\n' + block + 'auth required pam_debug.so auth=' + password + '\n'
        config += 'account required pam_debug.so acct=' + account + '\n'
        with tempfile.TemporaryDirectory(prefix='gxfp-pam-test-') as directory:
            (Path(directory) / 'test').write_text(config)
            return subprocess.run([str(HERE / 'pam_probe'), directory, 'test', 'nobody'],
                                  capture_output=True, text=True, timeout=5)

    def test_fingerprint_success_skips_failing_password(self):
        self.assertEqual(self.run_stack().returncode, 0)

    def test_fingerprint_failure_reaches_successful_password(self):
        self.assertEqual(self.run_stack(finger='auth_err', password='success').returncode, 0)

    def test_fingerprint_system_error_still_allows_password(self):
        self.assertEqual(self.run_stack(finger='system_err', password='success').returncode, 0)

    def test_both_methods_failing_rejects_authentication(self):
        self.assertEqual(self.run_stack(finger='auth_err').returncode, 1)

    def test_closed_lid_cannot_use_even_successful_fingerprint(self):
        self.assertEqual(self.run_stack(closed=True).returncode, 1)

    def test_closed_lid_allows_successful_password(self):
        self.assertEqual(self.run_stack(closed=True, password='success').returncode, 0)

    def test_required_lockout_failure_survives_successful_fingerprint(self):
        self.assertEqual(self.run_stack(preauth='auth_err', password='success').returncode, 1)

    def test_account_failure_survives_successful_authentication(self):
        self.assertEqual(self.run_stack(account='perm_denied').returncode, 1)


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gxfp-pam-plan-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.etc, self.vendor = self.root / 'pam', self.root / 'vendor'
        self.etc.mkdir()
        self.vendor.mkdir()
        self.base = '#%PAM-1.0\nauth include system-auth\naccount include system-auth\nsession include system-auth\n'
        for name in ('sudo', 'polkit-1', 'sddm'):
            (self.etc / name).write_text(self.base)
        self.shared = 'auth required pam_faillock.so preauth silent deny=10 unlock_time=120\n'
        (self.etc / 'system-auth').write_text(self.shared)

    def test_exact_scoped_services_and_unchanged_original_lines(self):
        plan = integration.prepare(self.etc, self.vendor)
        self.assertEqual([e['service'] for e in plan['services']], list(integration.SERVICES))
        for entry in plan['services']:
            self.assertNotEqual(entry['target'], str(self.etc / 'system-auth'))
            if entry['service'] != 'omarchy-lock-fingerprint':
                self.assertIn(self.base.split('\n', 1)[1], entry['content'])
        self.assertEqual((self.etc / 'system-auth').read_text(), self.shared)

    def test_vendor_polkit_is_copied_with_all_original_checks(self):
        (self.etc / 'polkit-1').unlink()
        (self.vendor / 'polkit-1').write_text(self.base)
        entry = integration.prepare(self.etc, self.vendor)['services'][1]
        self.assertFalse(entry['previously_present'])
        self.assertEqual(entry['source']['path'], str(self.vendor / 'polkit-1'))
        self.assertIn('account include system-auth', entry['content'])

    def test_sddm_preserves_guards_before_sufficient_fingerprint(self):
        text = integration.prepare(self.etc, self.vendor)['services'][2]['content']
        self.assertLess(text.index('pam_nologin.so'), text.index('pam_fprintd.so'))
        self.assertLess(text.index('pam_shells.so'), text.index('pam_fprintd.so'))

    def test_authsucc_uses_the_actual_preauth_lockout_parameters(self):
        text = integration.prepare(self.etc, self.vendor)['services'][0]['content']
        self.assertIn('pam_faillock.so authsucc deny=10 unlock_time=120', text)
        self.assertIn('pam_exec.so quiet type=auth', text)

    def test_existing_fingerprint_or_symlink_requires_review(self):
        (self.etc / 'sudo').write_text(self.base + 'auth sufficient pam_fprintd.so\n')
        with self.assertRaises(ValueError):
            integration.prepare(self.etc, self.vendor)
        (self.etc / 'sudo').unlink()
        (self.etc / 'sudo').symlink_to(self.etc / 'sddm')
        with self.assertRaises(ValueError):
            integration.prepare(self.etc, self.vendor)

    def test_changed_sources_abort_before_apply(self):
        plan = integration.prepare(self.etc, self.vendor)
        (self.etc / 'sddm').write_text(self.base + '# concurrent change\n')
        with self.assertRaisesRegex(ValueError, 'changed'):
            integration.apply(plan, self.etc, self.root / 'backup', owner=os.geteuid())
        self.assertFalse((self.etc / 'omarchy-lock-fingerprint').exists())

    def test_interrupted_write_restores_prior_content(self):
        plan = integration.prepare(self.etc, self.vendor)
        actual_atomic = integration.atomic_file
        def atomic(path, data, mode=0o644):
            if path == self.etc / 'sddm' and integration.BEGIN.encode() in data:
                raise OSError('Synthetic interrupted update')
            return actual_atomic(path, data, mode)
        real_regular = integration.regular
        def regular(path):
            data, info = real_regular(path)
            if str(path).startswith(('/usr/lib/security/', '/usr/bin/omarchy-')):
                values = list(info); values[4] = 0
                info = os.stat_result(values)
            return data, info
        with patch.object(integration, 'atomic_file', side_effect=atomic), \
                patch.object(integration, 'regular', side_effect=regular):
            with self.assertRaisesRegex(OSError, 'interrupted'):
                integration.apply(plan, self.etc, self.root / 'backup', owner=os.geteuid())
        for name in ('sudo', 'polkit-1', 'sddm'):
            self.assertEqual((self.etc / name).read_text(), self.base)
        self.assertFalse((self.etc / 'omarchy-lock-fingerprint').exists())


if __name__ == '__main__':
    unittest.main()
