#!/usr/bin/env python3
"""Transactional original Engine candidate rollout, with an empty-reader gate.

Run through local pkexec with an explicitly pinned build manifest. All project
assets are copied into an immutable root-owned release before services change.
One ordinary fprintd Claim/Release must succeed before committing the rollout.
Previous releases, old fingerprints, GUI launchers and PAM are never deleted or
changed. Fingerprint cleanup is a separate, later operation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
ROOT = Path('/opt/gxfp51b7')
MANIFEST = 'native-sgx/engine-service-build/build.json'
BACKEND = 'gxfp51b7-backend.service'
FPRINTD = 'fprintd.service'
CONFIGURATION = {
    Path('/etc/systemd/system/gxfp51b7-backend.service'): 'native-sgx/gxfp51b7-engine-backend.service',
    Path('/etc/systemd/system/fprintd.service.d/50-goodix-native.conf'): 'native-sgx/fprintd-engine.conf',
}
LINKS = {
    'lib/libfprint-2.so.2': '../libfprint/build-engine/libfprint/libfprint-2.so.2.0.0',
    'lib/libfprint-2.so': '../libfprint/build-engine/libfprint/libfprint-2.so.2.0.0',
    'lib/libgusb.so.2': '../linux-driver/build-tools/root/usr/lib/libgusb.so.2.0.10',
    'lib/libgusb.so': '../linux-driver/build-tools/root/usr/lib/libgusb.so.2.0.10',
}
EXECUTABLE = 'native-sgx/engine-service-build/engine_service_runner'


def emit(event, **fields):
    print(json.dumps(dict(event=event, **fields), separators=(',', ':')), flush=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read_regular(path, maximum=32 * 1024 * 1024, owner=None):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_size > maximum or info.st_nlink != 1 or
                (owner is not None and (info.st_uid != owner or info.st_mode & 0o022))):
            raise RuntimeError('Unexpected installation input type or ownership')
        data = source.read(maximum + 1)
        if len(data) != info.st_size:
            raise RuntimeError('Installation input changed while reading')
        return data


def checked_inputs(project, expected_manifest):
    if not re.fullmatch('[0-9a-f]{64}', expected_manifest):
        raise ValueError('Pin the exact prepared build manifest SHA256')
    raw = read_regular(project / MANIFEST, maximum=1024 * 1024)
    if digest(raw) != expected_manifest:
        raise RuntimeError('Original Engine manifest differs from the approved build')
    manifest = json.loads(raw)
    if (manifest.get('schema') != 1 or manifest.get('probe') != 'original-engine-service' or
            manifest.get('kernel') != os.uname().release):
        raise RuntimeError('Unexpected original Engine build or running kernel')
    files = manifest.get('checked_files')
    if type(files) is not dict or not 1 <= len(files) <= 512 or MANIFEST in files:
        raise RuntimeError('Unexpected original Engine dependency list')
    checked = {MANIFEST: raw}
    total = 0
    for name, expected in files.items():
        relative = PurePosixPath(name) if type(name) is str else None
        if (relative is None or relative.is_absolute() or str(relative) != name or
                any(part in ('.', '..') for part in relative.parts) or not relative.parts or
                type(expected) is not str or not re.fullmatch('[0-9a-f]{64}', expected)):
            raise RuntimeError('Unsafe original Engine dependency path')
        source = project / name
        if not source.resolve(strict=True).is_relative_to(project.resolve(strict=True)):
            raise RuntimeError('Original Engine dependency escapes the source tree')
        data = read_regular(source)
        total += len(data)
        if total > 128 * 1024 * 1024 or digest(data) != expected:
            raise RuntimeError('Original Engine dependency hash or resource bound failed')
        checked[name] = data
    required = {'native-sgx/engine_build.py', EXECUTABLE, *CONFIGURATION.values(),
                'native-sgx/check_engine_candidate.py', 'native-sgx/install_engine_candidate.py'}
    for target in LINKS.values():
        normalized = Path(os.path.normpath('lib/' + target)).as_posix()
        required.add(normalized)
    if not required.issubset(checked):
        raise RuntimeError('Incomplete candidate installation closure')
    return raw, manifest, checked


def protected_directory(path, owner=0):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise RuntimeError('Unsafe installation directory')


def file_mode(name):
    return 0o755 if name == EXECUTABLE else 0o644


def verify_release(release, checked, owner=0):
    protected_directory(release, owner)
    directories = {''}
    for name in set(checked) | set(LINKS):
        directories.update(str(parent) for parent in PurePosixPath(name).parents if str(parent) != '.')
    expected_paths = set(checked) | set(LINKS) | directories
    actual = set()
    for path in [release, *release.rglob('*')]:
        name = path.relative_to(release).as_posix() if path != release else ''
        info = path.lstat()
        if info.st_uid != owner:
            raise RuntimeError('Unexpected installed asset owner')
        if name in directories:
            protected_directory(path, owner)
        elif name in LINKS:
            if not stat.S_ISLNK(info.st_mode) or path.readlink().as_posix() != LINKS[name]:
                raise RuntimeError('Unexpected installed library link')
        elif name in checked:
            if stat.S_IMODE(info.st_mode) != file_mode(name) or read_regular(path, owner=owner) != checked[name]:
                raise RuntimeError('Installed asset differs from its pinned source')
        else:
            raise RuntimeError('Unexpected installed release entry')
        actual.add(name)
    if actual != expected_paths:
        raise RuntimeError('Incomplete original Engine release')


def prepare_release(root, checked, manifest_hash, owner=0):
    root.mkdir(exist_ok=True, mode=0o755)
    protected_directory(root, owner)
    releases = root / 'releases'
    releases.mkdir(exist_ok=True, mode=0o755)
    protected_directory(releases, owner)
    release = releases / manifest_hash[:16]
    if release.exists() or release.is_symlink():
        verify_release(release, checked, owner)
        return release
    stage = releases / ('.engine-stage-' + str(os.getpid()))
    stage.mkdir(mode=0o755)
    try:
        for name, data in checked.items():
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            with destination.open('xb') as output:
                output.write(data)
            destination.chmod(file_mode(name))
        for name, target in LINKS.items():
            path = stage / name
            path.parent.mkdir(exist_ok=True, mode=0o755)
            path.symlink_to(target)
        verify_release(stage, checked, owner)
        os.rename(stage, release)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return release


def atomic_file(path, data, mode=0o644):
    if path.is_symlink():
        raise RuntimeError('Refusing a configuration symlink')
    temporary = path.with_name(path.name + '.engine-new-' + str(os.getpid()))
    created = False
    try:
        with temporary.open('xb') as output:
            created = True
            output.write(data)
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def atomic_pointer(current, target):
    temporary = current.with_name('current.engine-new-' + str(os.getpid()))
    temporary.symlink_to(target)
    try:
        os.replace(temporary, current)
    finally:
        temporary.unlink(missing_ok=True)


class System:
    def command(self, action, unit=None):
        result = subprocess.run(['/usr/bin/systemctl', action] + ([unit] if unit else []),
                                capture_output=True, timeout=200, check=False)
        if action == 'start':
            # Type=notify waits for normal startup. If systemd's existing
            # Restart=on-failure recovery is already pending, wait for that
            # bounded recovery instead of claiming that rollback is complete.
            deadline = time.monotonic() + 45
            while True:
                state = subprocess.check_output(['/usr/bin/systemctl', 'show', unit,
                                                 '--property=ActiveState', '--value'],
                                                text=True, timeout=5).strip()
                if state == 'active':
                    return
                if state not in ('inactive', 'activating', 'failed') or time.monotonic() >= deadline:
                    raise RuntimeError('Fingerprint service did not become active')
                time.sleep(.5)
        if result.returncode:
            raise RuntimeError('Fingerprint service ' + action + ' failed')
        if action == 'stop':
            if self.state(unit) != 'inactive':
                raise RuntimeError('Fingerprint service did not reach its expected state')

    def state(self, unit):
        result = subprocess.check_output(['/usr/bin/systemctl', 'show', unit,
                                          '--property=ActiveState', '--value'], text=True, timeout=5).strip()
        if result not in ('active', 'inactive'):
            raise RuntimeError('Fingerprint service is not stably active or inactive')
        return result


def wait_for_fprintd_exit(system, seconds=45, clock=time.monotonic, sleep=time.sleep):
    """Let PAM's own fingerprint daemon exit without stopping a live client.

    Local Polkit authentication now uses pam_fprintd, which activates fprintd
    even when password fallback ultimately authorizes this installer. Wait for
    its normal idle exit, then let the transaction recheck the live state.
    """
    deadline = clock() + seconds
    waiting = False
    while system.state(FPRINTD) != 'inactive':
        if not waiting:
            emit('waiting_for_fprintd_idle_exit', maximum_seconds=seconds)
            waiting = True
        if clock() >= deadline:
            raise RuntimeError('fprintd remained active; leave the existing user operation untouched')
        sleep(.5)


def apply_transaction(current, release, updates, system, probe, unchanged, owner=0):
    """Switch only idle services; restore prior code/configuration on any failure."""
    if not current.is_symlink():
        raise RuntimeError('Expected the existing protected release pointer')
    previous = current.readlink()
    if not re.fullmatch(r'releases/[0-9a-f]{16}', previous.as_posix()):
        raise RuntimeError('Unexpected previous release pointer')
    previous_configs = {}
    for path in updates:
        protected_directory(path.parent, owner)
        data = read_regular(path, maximum=65536, owner=owner)
        previous_configs[path] = (data, stat.S_IMODE(path.lstat().st_mode))
    states = {unit: system.state(unit) for unit in (FPRINTD, BACKEND)}
    if states[FPRINTD] != 'inactive':
        raise RuntimeError('fprintd is active; leave the existing user operation untouched')
    changed = False
    try:
        if states[BACKEND] == 'active':
            system.command('stop', BACKEND)
        if system.state(FPRINTD) != 'inactive' or system.state(BACKEND) != 'inactive':
            raise RuntimeError('A fingerprint service activated during installation')
        changed = True
        atomic_pointer(current, Path('releases') / release.name)
        for path, data in updates.items():
            atomic_file(path, data)
        system.command('daemon-reload')
        system.command('start', BACKEND)
        system.command('start', FPRINTD)
        probe()
        unchanged()
    except BaseException as original:
        failures = []
        if changed:
            for unit in (FPRINTD, BACKEND):
                try:
                    system.command('stop', unit)
                except BaseException as error:
                    failures.append(error)
            try:
                atomic_pointer(current, previous)
                for path, (data, mode) in previous_configs.items():
                    atomic_file(path, data, mode)
                system.command('daemon-reload')
            except BaseException as error:
                failures.append(error)
        if not failures and states[BACKEND] == 'active':
            try:
                system.command('start', BACKEND)
            except BaseException as error:
                failures.append(error)
        if failures:
            raise BaseExceptionGroup('Candidate rollout and rollback failed', [original, *failures]) from None
        emit('previous_release_restored', release=previous.name)
        raise


def template_metadata():
    root = Path('/var/lib/fprint')
    if not root.exists():
        return None
    paths = [root, *root.rglob('*')]
    if len(paths) > 4096:
        raise RuntimeError('Unexpected fingerprint storage size')
    return {str(path.relative_to(root)): (info.st_ino, info.st_size, info.st_mtime_ns, info.st_mode, info.st_uid)
            for path in paths for info in (path.lstat(),)}


def pam_hashes():
    return {str(path): digest(path.read_bytes()) for path in Path('/etc/pam.d').iterdir() if path.is_file()}


def write_readiness_receipt(release, manifest_hash):
    directory = Path('/run/gxfp51b7-engine')
    protected_directory(directory)
    if stat.S_IMODE(directory.lstat().st_mode) != 0o700:
        raise RuntimeError('Unexpected original Engine runtime directory mode')
    receipt = dict(schema=1, probe='original-engine-service', release_id=release.name,
                   manifest_sha256=manifest_hash, kernel=os.uname().release,
                   boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                   completed_ns=time.time_ns(), claim_release_sessions=1,
                   transport_restored=True, old_templates_preserved=True, templates_deleted=False)
    atomic_file(directory / 'installation-ready.json',
                (json.dumps(receipt, sort_keys=True) + '\n').encode(), 0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True)
    parser.add_argument('--reader-is-empty', action='store_true', required=True,
                        help='Required for the one ordinary fprintd Claim/Release readiness check')
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise RuntimeError('Use local pkexec authentication as the UID1000 desktop owner')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if Path('/sys/class/dmi/id/product_name').read_text().strip() != 'MACHC-WAX9':
        raise RuntimeError('Unexpected computer')
    raw, manifest, checked = checked_inputs(PROJECT, args.manifest_sha256)
    system = System()
    wait_for_fprintd_exit(system)
    release = prepare_release(ROOT, checked, args.manifest_sha256)
    verifier = {'__name__': 'candidate_verifier', '__file__': str(release / 'native-sgx/engine_build.py')}
    exec(compile(checked['native-sgx/engine_build.py'], verifier['__file__'], 'exec'), verifier)
    verifier['verify_build'](release)
    before_templates, before_pam = template_metadata(), pam_hashes()
    def unchanged():
        if template_metadata() != before_templates or pam_hashes() != before_pam:
            raise RuntimeError('Fingerprint storage or PAM unexpectedly changed')
        write_readiness_receipt(release, args.manifest_sha256)
    def probe():
        subprocess.run(['/usr/bin/python3', '-B', str(release / 'native-sgx/check_engine_candidate.py'),
                        '--manifest-sha256', args.manifest_sha256],
                       env={'PATH': '/usr/bin', 'PKEXEC_UID': '1000', 'PYTHONDONTWRITEBYTECODE': '1'},
                       check=True, timeout=360)
    updates = {path: checked[name] for path, name in CONFIGURATION.items()}
    apply_transaction(ROOT / 'current', release, updates, system, probe, unchanged)
    emit('original_engine_candidate_installed', release=release.name, readiness_passed=True,
         old_templates_preserved=True, templates_deleted=False, pam_changed=False,
         adaptive_update_persisted=False)


if __name__ == '__main__':
    main()
