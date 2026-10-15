#!/usr/bin/env python3
"""Offline launcher gates, dependency validation and worker-factory ownership."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import run_engine_baseline_trial as launcher
import run_trial

sys.path.insert(0, str(launcher.PROJECT / 'sgx-vm'))


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.project = Path(self.directory.name)
        self.build = self.project / 'build'
        self.build.mkdir()
        self.asset = self.project / 'public-input'
        self.asset.write_bytes(b'public synthetic input')
        self.manifest = {'schema': 1, 'probe': 'original-engine-baseline',
                         'checked_files': {'public-input': hashlib.sha256(
                             self.asset.read_bytes()).hexdigest()}}
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(launcher, 'PROJECT', self.project))
        self.stack.enter_context(patch.object(launcher, 'BUILD', self.build))
        self.stack.enter_context(patch.object(launcher, 'BASELINE_REQUIRED_FILES',
                                             frozenset({'public-input'})))
        self.base = self.stack.enter_context(patch.object(launcher.run_engine_trial,
                                                          'verify_build'))

    def write_manifest(self):
        (self.build / 'baseline-build.json').write_text(json.dumps(self.manifest))

    def test_complete_dependency_mapping(self):
        self.write_manifest()
        self.assertEqual(launcher.verify_baseline_build(), self.manifest)
        self.base.assert_called_once_with()

    def test_base_build_must_validate_first(self):
        self.base.side_effect = ValueError('base build stale')
        with self.assertRaisesRegex(ValueError, 'base build stale'):
            launcher.verify_baseline_build()

    def test_missing_dependency_rejected(self):
        self.manifest['checked_files'] = {}
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            launcher.verify_baseline_build()

    def test_scope_rejected(self):
        self.manifest['probe'] = 'other-probe'
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'scope'):
            launcher.verify_baseline_build()

    def test_changed_dependency_rejected(self):
        self.write_manifest()
        self.asset.write_bytes(b'changed public synthetic input')
        with self.assertRaisesRegex(ValueError, 'build changed'):
            launcher.verify_baseline_build()

    def test_external_path_rejected_without_read(self):
        self.manifest['checked_files']['../not-a-project-file'] = '0' * 64
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'outside project'):
            launcher.verify_baseline_build()


class LauncherGateTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(launcher, 'verify_baseline_build'))
        self.uid = self.stack.enter_context(patch.object(launcher.os, 'geteuid', return_value=0))
        self.stack.enter_context(patch.dict(os.environ, {'PKEXEC_UID': '1000'}, clear=True))
        self.dmi = self.stack.enter_context(patch.object(Path, 'read_text',
                                                       side_effect=['HUAWEI\n', 'MACHC-WAX9\n']))
        self.open = self.stack.enter_context(patch.object(launcher.os, 'open', return_value=17))
        self.close = self.stack.enter_context(patch.object(launcher.os, 'close'))
        self.inherit = self.stack.enter_context(patch.object(launcher.os, 'set_inheritable'))
        self.limits = self.stack.enter_context(patch.object(launcher.resource, 'setrlimit'))
        self.quiesce = self.stack.enter_context(patch.object(launcher, 'quiesce_backend',
                                                            return_value=contextlib.nullcontext()))
        self.sealed = MagicMock(return_value=18)
        self.trial = MagicMock(return_value=0)
        self.stack.enter_context(patch.dict(sys.modules, {
            'sealed_input': SimpleNamespace(create_sealed_input=self.sealed),
            'run_trial': SimpleNamespace(run_tls_trial=self.trial),
        }))

    def assert_no_runtime_access(self):
        self.open.assert_not_called()
        self.sealed.assert_not_called()
        self.trial.assert_not_called()
        self.limits.assert_not_called()
        self.quiesce.assert_not_called()

    def test_offline_check_returns_before_identity_or_runtime_access(self):
        self.uid.return_value = 1000
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(launcher.main(['--check']), 0)
        self.assertFalse(json.loads(output.getvalue())['hardware_used'])
        self.uid.assert_not_called()
        self.dmi.assert_not_called()
        self.assert_no_runtime_access()

    def test_local_root_gate(self):
        self.uid.return_value = 1000
        with self.assertRaisesRegex(SystemExit, 'pkexec'):
            launcher.main([])
        self.dmi.assert_not_called()
        self.assert_no_runtime_access()

    def test_pkexec_user_gate(self):
        os.environ['PKEXEC_UID'] = '999'
        with self.assertRaisesRegex(SystemExit, 'pkexec'):
            launcher.main([])
        self.dmi.assert_not_called()
        self.assert_no_runtime_access()

    def test_machine_identity_gate(self):
        self.dmi.side_effect = ['OTHER\n']
        with self.assertRaisesRegex(SystemExit, 'Unexpected computer'):
            launcher.main([])
        self.assert_no_runtime_access()

    def test_handoff_uses_three_descriptor_factory_and_no_pixel_consumer(self):
        self.assertEqual(launcher.main([]), 0)
        self.open.assert_called_once_with('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
        self.inherit.assert_called_once_with(17, True)
        self.sealed.assert_called_once_with()
        self.trial.assert_called_once_with(17, 18, capture=True, image_consumer=None,
                                          runner_factory=launcher.runner_arguments,
                                          allow_sensor_identity=True)
        self.close.assert_not_called()

    def test_sealed_input_failure_closes_epc(self):
        self.sealed.side_effect = RuntimeError('synthetic failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic'):
            launcher.main([])
        self.close.assert_called_once_with(17)
        self.trial.assert_not_called()

    def test_descriptor_setup_failure_closes_epc_before_bios(self):
        self.inherit.side_effect = OSError('synthetic failure')
        with self.assertRaises(OSError):
            launcher.main([])
        self.close.assert_called_once_with(17)
        self.sealed.assert_not_called()

    def test_worker_failure_keeps_cleanup_with_transport_owner(self):
        self.trial.side_effect = RuntimeError('synthetic worker failure')
        with self.assertRaisesRegex(RuntimeError, 'synthetic worker'):
            launcher.main([])
        self.close.assert_not_called()


class FactoryTests(unittest.TestCase):
    def test_exact_worker_arguments(self):
        self.assertEqual(launcher.runner_arguments(11, 12, 13, True), [
            str(launcher.BUILD / 'engine_baseline_runner'), '11',
            str(launcher.BUILD / 'intel-le.plan'), str(launcher.INTEL / 'le_prod_css.bin'),
            str(launcher.BUILD / 'wbdi.plan'), str(launcher.BUILD / 'engine.plan'),
            str(launcher.ORIGINAL / 'sgx_white_list_cert.bin'), '12', '13'])

    def test_factory_requires_capture_and_descriptors(self):
        for args in ((11, 12, 13, False), (-1, 12, 13, True), (11, -1, 13, True),
                     (11, 12, -1, True)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                launcher.runner_arguments(*args)

    def run_factory_trial(self, supplied=False, failure=False):
        epc, sealed = os.pipe()
        self.addCleanup(self.close_if_open, epc)
        self.addCleanup(self.close_if_open, sealed)
        bridge = MagicMock()
        factory = MagicMock(return_value=['synthetic-worker'])
        if failure:
            factory.side_effect = ValueError('synthetic factory failure')
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch('tls_bridge.TlsBridge', return_value=bridge))
            stack.enter_context(patch('transport_server.serve_transport', return_value=1))
            fork = stack.enter_context(patch.object(run_trial.os, 'fork', return_value=1234567))
            stack.enter_context(patch.object(run_trial.os, 'waitpid', return_value=(1234567, 0)))
            default = stack.enter_context(patch.object(run_trial, 'runner_arguments',
                                                       MagicMock() if supplied else factory))
            kwargs = {'runner_factory': factory} if supplied else {}
            if failure:
                with self.assertRaisesRegex(ValueError, 'synthetic factory'):
                    run_trial.run_tls_trial(epc, sealed, capture=True, report=lambda _: None, **kwargs)
                fork.assert_not_called()
            else:
                self.assertEqual(run_trial.run_tls_trial(epc, sealed, capture=True,
                                                        report=lambda _: None, **kwargs), 0)
            if supplied:
                default.assert_not_called()
        factory.assert_called_once()
        args = factory.call_args.args
        self.assertEqual((args[0], args[1], args[3]), (epc, sealed, True))
        self.assertGreaterEqual(args[2], 0)
        bridge.close.assert_called_once_with()
        for fd in (epc, sealed):
            with self.assertRaises(OSError):
                os.fstat(fd)

    @staticmethod
    def close_if_open(fd):
        try:
            os.close(fd)
        except OSError:
            pass

    def test_existing_factory_remains_default(self):
        self.run_factory_trial()

    def test_optional_factory_receives_live_descriptors(self):
        self.run_factory_trial(supplied=True)

    def test_factory_failure_closes_transport_and_descriptors(self):
        self.run_factory_trial(supplied=True, failure=True)


class ServiceQuiescenceTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.state = self.stack.enter_context(patch.object(launcher, '_service_state'))
        self.command = self.stack.enter_context(patch.object(launcher, '_service_command'))
        self.output = self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def test_active_backend_stopped_then_restored(self):
        self.state.side_effect = ['inactive', 'active', 'inactive', 'inactive', 'active']
        with launcher.quiesce_backend():
            self.assertEqual(self.command.call_args.args, ('stop', 'gxfp51b7-backend.service', 65))
        self.assertEqual([c.args for c in self.command.call_args_list], [
            ('stop', 'gxfp51b7-backend.service', 65), ('start', 'gxfp51b7-backend.service', 130)])
        self.assertIn('baseline_backend_restored=1', self.output.getvalue())
        self.assertIn('baseline_backend_restore_elapsed_seconds=', self.output.getvalue())

    def test_inactive_backend_remains_inactive(self):
        self.state.side_effect = ['inactive'] * 4
        with launcher.quiesce_backend():
            pass
        self.command.assert_not_called()

    def test_active_fprintd_is_never_stopped(self):
        self.state.return_value = 'active'
        with self.assertRaisesRegex(RuntimeError, 'current user operation'):
            with launcher.quiesce_backend():
                self.fail('Active user operation must not enter the probe')
        self.command.assert_not_called()

    def test_probe_error_restores_initially_active_backend(self):
        self.state.side_effect = ['inactive', 'active', 'inactive', 'inactive', 'active']
        with self.assertRaisesRegex(ValueError, 'synthetic probe'):
            with launcher.quiesce_backend():
                raise ValueError('synthetic probe error')
        self.assertEqual(self.command.call_args.args, ('start', 'gxfp51b7-backend.service', 130))

    def test_stop_error_still_restores_initial_service_state(self):
        self.state.side_effect = ['inactive', 'active', 'active']
        self.command.side_effect = [RuntimeError('synthetic stop'), None]
        with self.assertRaisesRegex(RuntimeError, 'synthetic stop'):
            with launcher.quiesce_backend():
                self.fail('Failed stop must not enter the probe')
        self.assertEqual(self.command.call_count, 2)

    def test_new_fprintd_activation_aborts_before_probe(self):
        self.state.side_effect = ['inactive', 'active', 'inactive', 'active', 'active']
        with self.assertRaisesRegex(RuntimeError, 'became active'):
            with launcher.quiesce_backend():
                self.fail('New user operation must not enter the probe')
        self.assertEqual(self.command.call_args.args, ('start', 'gxfp51b7-backend.service', 130))

    def test_restore_failure_preserves_original_probe_error(self):
        self.state.side_effect = ['inactive', 'active', 'inactive', 'inactive']
        self.command.side_effect = [None, RuntimeError('synthetic restore')]
        with self.assertRaises(BaseExceptionGroup) as raised:
            with launcher.quiesce_backend():
                raise ValueError('synthetic probe')
        self.assertEqual([str(e) for e in raised.exception.exceptions],
                         ['synthetic probe', 'synthetic restore'])

    def test_restore_failure_after_success_is_reported(self):
        self.state.side_effect = ['inactive', 'active', 'inactive', 'inactive']
        self.command.side_effect = [None, RuntimeError('synthetic restore')]
        with self.assertRaisesRegex(RuntimeError, 'synthetic restore'):
            with launcher.quiesce_backend():
                pass


class ServiceCommandTests(unittest.TestCase):
    def test_command_uses_fixed_program_bounded_timeout_and_no_streaming(self):
        with patch.object(launcher.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as run:
            launcher._service_command('stop', 'gxfp51b7-backend.service', 65)
        run.assert_called_once_with(['/usr/bin/systemctl', 'stop', 'gxfp51b7-backend.service'],
                                    capture_output=True, timeout=65, check=False)

    def test_command_failure_does_not_export_output(self):
        result = SimpleNamespace(returncode=1, stdout=b'private-output', stderr=b'private-output')
        with patch.object(launcher.subprocess, 'run', return_value=result):
            with self.assertRaises(RuntimeError) as raised:
                launcher._service_command('stop', 'gxfp51b7-backend.service', 65)
        self.assertNotIn('private-output', str(raised.exception))

    def test_state_requires_stable_known_state(self):
        for value in ('activating', 'deactivating', 'failed', 'unknown'):
            with self.subTest(value=value), patch.object(launcher.subprocess, 'run',
                    return_value=SimpleNamespace(returncode=0, stdout=value)):
                with self.assertRaises(RuntimeError):
                    launcher._service_state('fprintd.service')


if __name__ == '__main__':
    unittest.main()
