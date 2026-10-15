"""Validate candidate manifests using synthetic public files, never real inputs."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import engine_build as build


class BuildManifestTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='engine-manifest-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'release'
        self.root.mkdir()
        files = {}
        for relative in build.REQUIRED_FILES:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(('Synthetic public asset: ' + relative).encode())
            files[relative] = build.digest(path)
        self.engine_relative = build.ORIGINAL + 'Engine_Enclave_3.02.00.signed.dll'
        self.engine_hash = files[self.engine_relative]
        self.pin = patch.object(build, 'ENGINE_SHA256', self.engine_hash)
        self.pin.start()
        self.addCleanup(self.pin.stop)
        checks = {'base_loader', 'kernel', 'worker', 'test_engine_service_action',
                  'test_engine_service_runner', 'test_engine_metadata',
                  'test_startup_factory', 'test_startup_baseline', 'test_startup_service',
                  'python', 'libfprint', 'libfprint_tests'}
        self.manifest = dict(schema=1, probe='original-engine-service', protocol=2, profile=12,
                             engine_sha256=self.engine_hash, adaptive_update_persisted=False,
                             requires_empty_start=True, hardware_used_during_build=False,
                             template_min_bytes=0x255, template_max_bytes=4 * 1024 * 1024,
                             capture_limit=512, session_limit_seconds=1200, kernel='synthetic-kernel',
                             checked_files=files,
                             checks={name: {'exit_code': 0} for name in checks})

    def save(self):
        path = self.root / build.BUILD_RELATIVE / 'build.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.manifest))

    def verify(self):
        self.save()
        return build.verify_build(self.root)

    def test_complete_public_manifest_passes(self):
        self.assertEqual(self.verify(), self.manifest)

    def test_missing_runtime_dependency_rejected(self):
        del self.manifest['checked_files']['native-sgx/engine_reader.py']
        with self.assertRaises(ValueError):
            self.verify()

    def test_changed_runtime_source_rejected(self):
        (self.root / 'native-sgx/engine_reader.py').write_text('changed synthetic source')
        with self.assertRaises(ValueError):
            self.verify()

    def test_path_escape_and_external_symlink_rejected(self):
        outside = Path(self.temporary.name) / 'outside'
        outside.write_bytes(b'public synthetic outside file')
        for relative in ('../outside', str(outside)):
            with self.subTest(relative=relative):
                self.manifest['checked_files'][relative] = build.digest(outside)
                with self.assertRaises(ValueError):
                    self.verify()
                del self.manifest['checked_files'][relative]
        relative = 'native-sgx/synthetic-alias'
        (self.root / relative).symlink_to(outside)
        self.manifest['checked_files'][relative] = build.digest(outside)
        with self.assertRaises(ValueError):
            self.verify()

    def test_original_engine_pin_cannot_be_replaced_by_manifest_hash(self):
        path = self.root / self.engine_relative
        path.write_bytes(b'A different synthetic engine')
        self.manifest['checked_files'][self.engine_relative] = build.digest(path)
        with self.assertRaises(ValueError):
            self.verify()

    def test_failed_check_rejected(self):
        self.manifest['checks']['worker']['exit_code'] = 1
        with self.assertRaises(ValueError):
            self.verify()

    def test_missing_mandatory_check_cannot_be_replaced_by_dummy_success(self):
        self.manifest['checks'] = {'dummy': {'exit_code': 0}}
        with self.assertRaises(ValueError):
            self.verify()

    def test_declared_limits_must_match_the_candidate_contract(self):
        for name, wrong in (('capture_limit', 1), ('session_limit_seconds', 0),
                            ('template_min_bytes', 0), ('template_max_bytes', 4 * 1024 * 1024 + 1)):
            with self.subTest(name=name):
                original = self.manifest[name]
                self.manifest[name] = wrong
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[name] = original

    def test_wrong_candidate_identity_or_adaptation_claim_is_rejected(self):
        for name, wrong in (('probe', 'original-engine-baseline'), ('protocol', 1),
                            ('profile', 13), ('adaptive_update_persisted', True),
                            ('requires_empty_start', False)):
            with self.subTest(name=name):
                original = self.manifest[name]
                self.manifest[name] = wrong
                with self.assertRaises(ValueError):
                    self.verify()
                self.manifest[name] = original


if __name__ == '__main__':
    unittest.main()
