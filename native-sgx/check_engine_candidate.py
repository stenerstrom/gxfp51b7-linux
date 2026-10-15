#!/usr/bin/env python3
"""Check one empty original-Engine session through ordinary fprintd Claim/Release.

No enrollment, verification, fingerprint listing, deletion, or PAM edits. The
exact backend instance must confirm clean native cleanup after D-Bus Release.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import pwd
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
UNIT = 'gxfp51b7-backend.service'
MODULES = ('gxfp51b7_native', 'gxfp51b7_probe', 'gxfp51b7_sealed',
           'gxfp51b7_otp', 'gxfp51b7_factory', 'gxfp51b7_engine',
           'gxfp51b7_engine_service')
CLOSE = re.compile(r'engine_worker_closed=1 exit=0 frames=1 restored=1')
FIELDS = '__CURSOR,__MONOTONIC_TIMESTAMP,_PID,_UID,_BOOT_ID,_SYSTEMD_UNIT,_SYSTEMD_INVOCATION_ID,MESSAGE'


def identity():
    output = subprocess.check_output(
        ['/usr/bin/systemctl', 'show', UNIT, '--property=MainPID,InvocationID,ActiveState'],
        text=True, timeout=5)
    values = dict(line.split('=', 1) for line in output.splitlines())
    pid, invocation = values.get('MainPID', ''), values.get('InvocationID', '')
    boot = Path('/proc/sys/kernel/random/boot_id').read_text().strip().replace('-', '')
    if (values.get('ActiveState') != 'active' or not re.fullmatch(r'[1-9][0-9]{0,9}', pid)
            or int(pid) >= 2**31 or not re.fullmatch('[0-9a-f]{32}', invocation)
            or not re.fullmatch('[0-9a-f]{32}', boot)):
        raise RuntimeError('Original Engine backend identity is not ready')
    return {'_PID': pid, '_UID': '0', '_BOOT_ID': boot, '_SYSTEMD_UNIT': UNIT,
            '_SYSTEMD_INVOCATION_ID': invocation}


def records(expected, cursor=None):
    subprocess.run(['/usr/bin/journalctl', '--sync'], check=True, timeout=5,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # JSON otherwise replaces MESSAGE values over 4096 bytes with null. Keep
    # complete fields for type validation; the total output bound still applies.
    args = ['/usr/bin/journalctl', '-b', '--no-pager', '--quiet', '--all', '-o', 'json',
            '--output-fields=' + FIELDS, '-n', '513' if cursor else '1']
    args += [key + '=' + value for key, value in expected.items() if key != '_UID']
    if cursor:
        args.append('--after-cursor=' + cursor)
    result = subprocess.check_output(args, text=True, timeout=5)
    if len(result) > 4 * 1024 * 1024:
        raise RuntimeError('Original Engine lifecycle evidence exceeds bounds')
    parsed = [json.loads(line) for line in result.splitlines()]
    if len(parsed) > 512:
        raise RuntimeError('Too many original Engine lifecycle records')
    for record in parsed:
        validate_record(record, expected)
    return parsed


def validate_record(record, expected):
    if type(record) is not dict or any(record.get(key) != value for key, value in expected.items()):
        raise RuntimeError('Unexpected lifecycle record source')
    cursor, stamp = record.get('__CURSOR'), record.get('__MONOTONIC_TIMESTAMP')
    if (type(cursor) is not str or not 1 <= len(cursor) <= 512 or
            any(not 33 <= ord(char) <= 126 for char in cursor) or
            type(stamp) is not str or not re.fullmatch('[0-9]{1,20}', stamp) or
            not 0 < int(stamp) < 2**64 or
            ('MESSAGE' in record and type(record['MESSAGE']) is not str)):
        raise RuntimeError('Malformed lifecycle record')


def clean_close_count(events, checkpoint, expected):
    seen = {checkpoint['__CURSOR']}
    count = 0
    for event in events:
        validate_record(event, expected)
        if (event['__CURSOR'] in seen or
                int(event['__MONOTONIC_TIMESTAMP']) <= int(checkpoint['__MONOTONIC_TIMESTAMP'])):
            raise RuntimeError('Stale or duplicate lifecycle evidence')
        seen.add(event['__CURSOR'])
        # Journal entries can have no MESSAGE field. Keep their authenticated
        # identity and freshness checks, but never use them as cleanup proof.
        if 'MESSAGE' not in event:
            continue
        message = event['MESSAGE']
        if message.startswith('engine_worker_closed='):
            if not CLOSE.fullmatch(message):
                raise RuntimeError('Original Engine cleanup was not successful')
            count += 1
    if count > 1:
        raise RuntimeError('Unexpected concurrent original Engine session')
    return count


def check_session():
    import gi
    gi.require_version('Gio', '2.0')
    from gi.repository import Gio, GLib
    expected = identity()
    previous = records(expected)
    if len(previous) != 1:
        raise RuntimeError('Original Engine lifecycle checkpoint unavailable')
    checkpoint = previous[0]
    # A private bus connection is released even if Claim times out. That lets
    # fprintd see owner loss and perform its normal cleanup during rollback.
    address = Gio.dbus_address_get_for_bus_sync(Gio.BusType.SYSTEM, None)
    flags = Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
    bus = Gio.DBusConnection.new_for_address_sync(address, flags, None, None)
    claimed = False
    try:
        def call(path, interface, method, arguments=None, timeout=10000):
            return bus.call_sync('net.reactivated.Fprint', path, interface, method, arguments,
                                 None, Gio.DBusCallFlags.NONE, timeout, None).unpack()
        path = call('/net/reactivated/Fprint/Manager', 'net.reactivated.Fprint.Manager',
                    'GetDefaultDevice')[0]
        interface = 'net.reactivated.Fprint.Device'
        properties = call(path, 'org.freedesktop.DBus.Properties', 'GetAll',
                          GLib.Variant('(s)', (interface,)))[0]
        if (properties.get('name') != 'Goodix ChicagoHS (original Engine)' or
                properties.get('num-enroll-stages') != 20):
            raise RuntimeError('fprintd did not select the original Engine candidate')
        call(path, interface, 'Claim', GLib.Variant('(s)', (pwd.getpwuid(1000).pw_name,)), timeout=150000)
        claimed = True
        call(path, interface, 'Release', timeout=150000)
        claimed = False
    finally:
        try:
            if claimed:
                call(path, interface, 'Release', timeout=150000)
        finally:
            bus.close_sync(None)
    deadline = time.monotonic() + 5
    while True:
        if identity() != expected:
            raise RuntimeError('Original Engine backend changed during readiness check')
        count = clean_close_count(records(expected, checkpoint['__CURSOR']), checkpoint, expected)
        remaining = [name for name in MODULES if Path('/sys/module', name).exists()]
        if count == 1 and not remaining:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError('Original Engine cleanup evidence is incomplete')
        time.sleep(.1)


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest-sha256', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise RuntimeError('Use local pkexec authentication as the UID1000 desktop owner')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    root = Path(__file__).resolve().parents[1]
    if (root.parent != Path('/opt/gxfp51b7/releases') or
            not re.fullmatch('[0-9a-f]{16}', root.name) or
            not re.fullmatch('[0-9a-f]{64}', args.manifest_sha256)):
        raise RuntimeError('Use the protected installed original Engine checker')
    from engine_build import BUILD_RELATIVE, verify_build
    manifest = root / BUILD_RELATIVE / 'build.json'
    if hashlib.sha256(manifest.read_bytes()).hexdigest() != args.manifest_sha256:
        raise RuntimeError('Unexpected installed original Engine manifest')
    for path in (root, Path(__file__).resolve(), manifest):
        info = path.lstat()
        if info.st_uid or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise RuntimeError('Original Engine checker is not protected')
    verify_build(root)
    check_session()
    print(json.dumps({'ready': True, 'claim_release_sessions': 1, 'transport_restored': True,
                      'templates_read': False, 'templates_saved': False, 'templates_deleted': False}))


if __name__ == '__main__':
    main()
