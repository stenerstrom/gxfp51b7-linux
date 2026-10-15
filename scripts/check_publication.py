#!/usr/bin/env python3
"""Reject runtime, generated, private or binary files in the Git publication."""
from pathlib import Path
import re
import subprocess

from import_vendor import load_assets

ROOT = Path(__file__).resolve().parents[1]


def main():
    raw = subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=ROOT)
    entries = [entry.split(b'\t', 1) for entry in raw.split(b'\0') if entry]
    if not entries:
        raise RuntimeError('Stage the reviewed source files first')
    blocked_suffixes = {'.dll', '.exe', '.bin', '.plan', '.ko', '.o', '.a', '.so',
                        '.gxfp', '.fprint', '.sealed', '.log', '.png', '.jpg', '.pcap', '.pyc'}
    forbidden_roots = {'windows-driver-1.1.151.18', 'linux-driver', '.tools'}
    for metadata, name in entries:
        mode, oid, stage = metadata.split()
        if mode not in (b'100644', b'100755') or stage != b'0':
            raise RuntimeError('Unexpected index entry type')
        path = Path(name.decode())
        source = ROOT / path
        if (path.suffix.lower() in blocked_suffixes or path.parts[0] in forbidden_roots or
                'private' in path.parts or '__pycache__' in path.parts or
                any(part.endswith('-build') or part.startswith('build-') for part in path.parts) or
                path.name in {'AGENTS.md', 'CLAUDE.md', 'plan.json'} or
                source.is_symlink() or not source.resolve().is_relative_to(ROOT)):
            raise RuntimeError('Unexpected publication path: ' + str(path))
        data = subprocess.check_output(['git', 'cat-file', 'blob', oid.decode('ascii')], cwd=ROOT)
        if (b'\0' in data or data.startswith((b'\x7fELF', b'MZ', b'PK\x03\x04')) or
                re.search(rb'-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----', data) or
                re.search(rb'gh[pousr]_[A-Za-z0-9]{30,}', data) or
                re.search(rb'/home/[A-Za-z0-9_-]+/(?:Work|Downloads|\.config|\.local)/', data)):
            raise RuntimeError('Non-public content in: ' + str(path))
    for entry in load_assets()['files']:
        subprocess.run(['git', 'check-ignore', '-q', entry['destination']], cwd=ROOT, check=True)
    # There must be no staged changes to ignored runtime assets, even after a
    # successful full build. The path and content checks above inspect the index
    # allowlist, not other files in the development workspace.
    print(f'Publication check passed for {len(entries)} source/documentation files.')


if __name__ == '__main__':
    main()
