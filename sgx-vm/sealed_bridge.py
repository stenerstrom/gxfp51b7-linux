#!/usr/bin/env python3
"""Read only the encrypted BIOS SGX object into RAM; always unload its reader."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
DEVICE = Path('/sys/bus/platform/devices/GXFP51B7:00')


def read_sealed_blob():
    if os.geteuid() != 0 or not (os.environ.get('PKEXEC_UID') == '1000' or
                               os.environ.get('GXFP51B7_SERVICE') == '1'):
        raise RuntimeError('Encrypted BIOS transfer requires pkexec as the UID1000 desktop owner')
    if (DEVICE / 'driver').exists():
        raise RuntimeError('Fingerprint device already has a driver')
    for name in ('gxfp51b7_native', 'gxfp51b7_probe', 'gxfp51b7_sealed'):
        if Path('/sys/module', name).exists():
            raise RuntimeError('A fingerprint probe is already loaded')
    loaded, data = False, bytearray()
    try:
        subprocess.run(['/usr/bin/insmod', str(ROOT / 'native-probe/gxfp51b7_sealed.ko')],
                       check=True)
        loaded = True
        length = int(Path('/sys/module/gxfp51b7_sealed/parameters/sealed_length').read_text())
        if not 0x230 <= length <= 2044:
            raise RuntimeError('No bounded SGX sealed BIOS object')
        with (DEVICE / 'sgx_sealed').open('rb', buffering=0) as source:
            data = bytearray(length)
            count = source.readinto(data)
            if count != length or source.read(1):
                raise RuntimeError('Unexpected encrypted BIOS transfer length')
        return data
    except BaseException:
        data[:] = b'\0' * len(data)
        raise
    finally:
        if loaded:
            try:
                subprocess.run(['/usr/bin/rmmod', 'gxfp51b7_sealed'], check=True)
            except BaseException:
                data[:] = b'\0' * len(data)
                raise
        if loaded and ((DEVICE / 'driver').exists() or
                       Path('/sys/module/gxfp51b7_sealed').exists()):
            data[:] = b'\0' * len(data)
            raise RuntimeError('Temporary BIOS reader cleanup incomplete')
