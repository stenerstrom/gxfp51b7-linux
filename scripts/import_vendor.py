#!/usr/bin/env python3
"""Import only the five exact, externally supplied signed runtime assets."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = {
    'goodix': 'windows-driver-1.1.151.18/extracted/source',
    'intel': 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10',
}
NAMES = {
    'goodix': {'Engine_Enclave_3.02.00.signed.dll', 'WBDI_Enclave.signed.dll',
               'sgx_white_list_cert.bin'},
    'intel': {'le.signed.dll', 'le_prod_css.bin'},
}


def load_assets(root=ROOT):
    assets = json.loads((root / 'vendor-assets.json').read_text())
    if assets.get('schema') != 1 or type(assets.get('files')) is not list or len(assets['files']) != 5:
        raise ValueError('Expected the five-asset pilot manifest')
    seen = set()
    for entry in assets['files']:
        provider, name = entry.get('provider'), entry.get('name')
        if provider not in NAMES or name not in NAMES[provider] or name in seen:
            raise ValueError('Unknown or duplicate asset identity')
        expected = DIRECTORIES[provider] + '/' + name
        if (entry.get('destination') != expected or
                not (root / expected).resolve().is_relative_to(root.resolve())):
            raise ValueError('Asset destination is outside its ignored directory')
        if (type(entry.get('bytes')) is not int or not 0 < entry['bytes'] <= 32 * 1024 * 1024 or
                not re.fullmatch('[0-9a-f]{64}', entry.get('sha256', ''))):
            raise ValueError('Invalid asset size or digest')
        seen.add(name)
    return assets


def verify(path, entry):
    if not path.is_file() or path.stat().st_size != entry['bytes']:
        raise ValueError('Unexpected asset size: ' + entry['name'])
    with path.open('rb') as stream:
        actual = hashlib.file_digest(stream, 'sha256').hexdigest()
    if actual != entry['sha256']:
        raise ValueError('Unexpected asset hash: ' + entry['name'])


def verify_all(root=ROOT):
    assets = load_assets(root)
    for entry in assets['files']:
        verify(root / entry['destination'], entry)
    return assets


def import_assets(goodix_directory, intel_directory, root=ROOT):
    assets = load_assets(root)
    pending = []
    # Validate every input before copying anything. Never search for keys,
    # fingerprint templates, images, or names other than this fixed allowlist.
    for entry in assets['files']:
        directory = {'goodix': goodix_directory, 'intel': intel_directory}[entry['provider']]
        direct = directory / entry['name']
        matches = [direct] if direct.is_file() else sorted(directory.rglob(entry['name']))
        if len(matches) != 1:
            raise ValueError('Expected exactly one file: ' + entry['name'])
        verify(matches[0], entry)
        pending.append((matches[0], entry))
    for source, entry in pending:
        target = root / entry['destination']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        verify(target, entry)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--goodix-dir', type=Path)
    parser.add_argument('--intel-dir', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        verify_all()
        print('Verified all five external runtime assets.')
        return
    if not args.goodix_dir or not args.intel_dir:
        parser.error('Provide both extracted package directories, or --check.')
    import_assets(args.goodix_dir, args.intel_dir)
    print('Imported five hash-verified assets into ignored local directories.')


if __name__ == '__main__':
    main()
