#!/usr/bin/env python3
"""Prepare or apply scoped fingerprint PAM integration on this Omarchy host.

The plan binds existing files by hash. Only the listed local service stacks
are changed; originals are saved in a root-owned rollback directory. No
fingerprint contents are read, and no authentication is automatically granted.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

SERVICES = ('sudo', 'polkit-1', 'sddm', 'omarchy-lock-fingerprint')
BEGIN = '# BEGIN gxfp51b7 fingerprint authentication'
END = '# END gxfp51b7 fingerprint authentication'
MODULE = 'pam_fprintd.so max-tries=1 timeout=15'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint_block(preauth):
    return '\n'.join((BEGIN, preauth,
        'auth [success=2 default=ignore] pam_exec.so quiet type=auth /usr/bin/omarchy-hw-laptop-closed',
        'auth [success=ok default=1] ' + MODULE,
        'auth sufficient pam_faillock.so authsucc ' + ' '.join(
            option for option in preauth.split()[3:] if '=' in option), END)) + '\n'


def render(service, base, preauth):
    if service == 'omarchy-lock-fingerprint':
        if base is not None:
            raise ValueError('An existing lock fingerprint stack must be reviewed separately')
        return '#%PAM-1.0\n' + BEGIN + '\nauth required ' + MODULE + '\n' + END + '\naccount include system-local-login\n'
    if base is None or not base.startswith('#%PAM-1.0'):
        raise ValueError('Unexpected original service stack')
    if 'pam_fprintd.so' in base or BEGIN in base:
        raise ValueError('Fingerprint authentication is already configured; inspect it first')
    header, rest = base.split('\n', 1)
    guards = ('auth required pam_shells.so\nauth requisite pam_nologin.so\n'
              if service == 'sddm' else '')
    return header + '\n' + guards + fingerprint_block(preauth) + rest


def prepare(etc=Path('/etc/pam.d'), vendor=Path('/usr/lib/pam.d')):
    system_auth = (etc / 'system-auth').read_text()
    preauth = [line for line in system_auth.splitlines() if re.match(r'^auth\s+required\s+pam_faillock\.so\s+preauth\b', line)]
    if len(preauth) != 1:
        raise ValueError('The actual account-lock preauth policy needs separate review')
    entries = []
    for service in SERVICES:
        target = etc / service
        origin = target if target.exists() else vendor / service
        if service == 'omarchy-lock-fingerprint' and not target.exists():
            base = None
            source = None
        else:
            info = origin.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('PAM source is not a regular file')
            raw = origin.read_bytes()
            base = raw.decode()
            source = dict(path=str(origin), sha256=sha(raw), mode=stat.S_IMODE(info.st_mode))
        entries.append(dict(service=service, target=str(target), previously_present=target.exists(),
                            source=source, content=render(service, base, preauth[0])))
    return dict(schema=1, scope='gxfp51b7-omarchy-pam', services=entries,
                system_auth_sha256=sha(system_auth.encode()),
                fingerprint_timeout_seconds=15, password_fallback=True)


def regular(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(fd, 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            raise ValueError('Unexpected PAM input')
        return f.read(), info


def atomic_file(path, data, mode=0o644):
    temporary = path.with_name(path.name + '.gxfp-new-' + str(os.getpid()))
    made = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        made = True
        with os.fdopen(fd, 'wb') as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if made:
            temporary.unlink(missing_ok=True)


def apply(plan, etc=Path('/etc/pam.d'), backup_root=Path('/var/lib/gxfp51b7/pam-backups'), owner=0):
    if plan != prepare(etc):
        raise ValueError('PAM files changed after the reviewed plan was prepared')
    for module in ('pam_fprintd.so', 'pam_faillock.so', 'pam_exec.so'):
        path = Path('/usr/lib/security') / module
        data, info = regular(path)
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('PAM module is not protected')
    data, info = regular(Path('/usr/bin/omarchy-hw-laptop-closed'))
    if info.st_uid or info.st_mode & 0o022:
        raise ValueError('Lid check is not protected')
    for path in (etc,):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise ValueError('PAM directory is not protected')
    original = {}
    for entry in plan['services']:
        target = Path(entry['target'])
        if target.parent != etc or target.name not in SERVICES or target.is_symlink():
            raise ValueError('Unexpected PAM target')
        if target.exists():
            data, info = regular(target)
            if info.st_uid != owner or info.st_mode & 0o022:
                raise ValueError('Existing PAM file is not protected')
            original[target] = (data, stat.S_IMODE(info.st_mode))
        else:
            original[target] = None
    backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = backup_root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError('PAM backup directory is not protected')
    backup = backup_root / (str(time.time_ns()) + '-' + sha(json.dumps(plan, sort_keys=True).encode())[:12])
    backup.mkdir(mode=0o700)
    for target, previous in original.items():
        if previous is not None:
            atomic_file(backup / target.name, previous[0], 0o600)
    atomic_file(backup / 'restore.json', json.dumps({target.name: None if previous is None else previous[1]
                for target, previous in original.items()}, indent=2).encode() + b'\n', 0o600)
    applied = []
    try:
        for entry in plan['services']:
            target = Path(entry['target'])
            atomic_file(target, entry['content'].encode())
            applied.append(target)
        for entry in plan['services']:
            data, info = regular(Path(entry['target']))
            if data != entry['content'].encode() or info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o644:
                raise ValueError('Installed PAM content or ownership differs')
        if sha((etc / 'system-auth').read_bytes()) != plan['system_auth_sha256']:
            raise ValueError('Shared password authentication changed unexpectedly')
    except BaseException as original_error:
        failures = []
        for target in reversed(applied):
            try:
                previous = original[target]
                if previous is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_file(target, previous[0], previous[1])
            except BaseException as rollback_error:
                failures.append(rollback_error)
        if failures:
            raise BaseExceptionGroup('PAM integration and rollback failed', [original_error, *failures]) from None
        raise
    return backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--apply', type=Path)
    parser.add_argument('--sha256')
    args = parser.parse_args()
    if bool(args.plan) == bool(args.apply):
        parser.error('Choose --plan output.json or --apply reviewed.json --sha256 HASH')
    if args.plan:
        plan = prepare()
        args.plan.write_text(json.dumps(plan, indent=2) + '\n')
        print(json.dumps({'prepared': True, 'services': list(SERVICES), 'password_fallback': True,
                          'sha256': sha(args.plan.read_bytes())}))
        return
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise RuntimeError('Use local pkexec authentication as the authorized desktop owner')
    raw, _ = regular(args.apply)
    if not re.fullmatch('[0-9a-f]{64}', args.sha256 or '') or sha(raw) != args.sha256:
        raise ValueError('Reviewed PAM plan hash does not match')
    backup = apply(json.loads(raw))
    print(json.dumps({'installed': True, 'services': list(SERVICES), 'backup': str(backup),
                      'password_fallback': True, 'fingerprint_timeout_seconds': 15}))


if __name__ == '__main__':
    main()
