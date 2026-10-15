"""Exercise asset-import isolation with synthetic files, never real assets."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import import_vendor as vendor


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='gxfp-import-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'checkout'
        self.root.mkdir()
        self.goodix = self.root.parent / 'goodix'
        self.intel = self.root.parent / 'intel'
        self.goodix.mkdir()
        self.intel.mkdir()
        self.manifest = {'schema': 1, 'files': []}
        for provider, names in vendor.NAMES.items():
            for name in sorted(names):
                data = ('synthetic public asset ' + name).encode()
                source = (self.goodix if provider == 'goodix' else self.intel) / name
                source.write_bytes(data)
                self.manifest['files'].append(dict(provider=provider, name=name,
                    destination=vendor.DIRECTORIES[provider] + '/' + name,
                    bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
        self.save()

    def save(self):
        (self.root / 'vendor-assets.json').write_text(json.dumps(self.manifest))

    def test_imports_only_five_checked_files_and_verifies_them(self):
        (self.goodix / 'unrelated-private-file').write_text('must not be copied')
        vendor.import_assets(self.goodix, self.intel, self.root)
        vendor.verify_all(self.root)
        self.assertEqual(len([p for p in self.root.rglob('*') if p.is_file()]), 6)

    def test_wrong_size_or_hash_prevents_every_copy(self):
        source = self.intel / 'le_prod_css.bin'
        for value in (b'wrong size', b'x' * source.stat().st_size):
            with self.subTest(value=len(value)):
                source.write_bytes(value)
                with self.assertRaises(ValueError):
                    vendor.import_assets(self.goodix, self.intel, self.root)
                self.assertEqual(list(self.root.iterdir()), [self.root / 'vendor-assets.json'])

    def test_unknown_duplicate_and_outside_destinations_rejected(self):
        original = dict(self.manifest['files'][0])
        mutations = ({'provider': 'typo'}, {'destination': '/tmp/outside.dll'},
                     {'destination': '../outside.dll'}, {'destination': 'tracked.dll'},
                     {'name': 'unlisted.dll'})
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.manifest['files'][0] = original | mutation
                self.save()
                with self.assertRaises(ValueError): vendor.load_assets(self.root)
        self.manifest['files'][0] = dict(self.manifest['files'][1])
        self.save()
        with self.assertRaises(ValueError): vendor.load_assets(self.root)

    def test_missing_and_empty_manifests_rejected(self):
        for entries in ([], self.manifest['files'][:-1]):
            self.manifest['files'] = entries
            self.save()
            with self.assertRaises(ValueError): vendor.load_assets(self.root)

    def test_symlinked_destination_outside_checkout_rejected(self):
        outside = self.root.parent / 'outside'
        outside.mkdir()
        (self.root / 'windows-driver-1.1.151.18').symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError): vendor.load_assets(self.root)

    def test_direct_file_takes_precedence_over_nested_package_copy(self):
        nested = self.goodix / 'SGXDriver'
        nested.mkdir()
        (nested / 'WBDI_Enclave.signed.dll').write_text('different unselected package copy')
        vendor.import_assets(self.goodix, self.intel, self.root)
        vendor.verify_all(self.root)

    def test_ambiguous_recursive_search_and_missing_file_rejected(self):
        source = self.goodix / 'WBDI_Enclave.signed.dll'
        data = source.read_bytes()
        source.unlink()
        with self.assertRaises(ValueError): vendor.import_assets(self.goodix, self.intel, self.root)
        for name in ('a', 'b'):
            (self.goodix / name).mkdir()
            (self.goodix / name / source.name).write_bytes(data)
        with self.assertRaises(ValueError): vendor.import_assets(self.goodix, self.intel, self.root)


if __name__ == '__main__':
    unittest.main()
