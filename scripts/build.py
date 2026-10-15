#!/usr/bin/env python3
"""Build the pilot from a clean checkout, without opening any hardware."""
import json
import os
from pathlib import Path
import random
import shutil
import struct
import subprocess
import sys
import zlib

from import_vendor import verify_all

ROOT = Path(__file__).resolve().parents[1]


def synthetic_fixture():
    """Generate RGB noise for upstream frame assembly; contains no biometrics."""
    width, height = 96, 123
    rng = random.Random(51_007)
    rows = bytearray()
    for _ in range(height):
        rows.append(0)  # PNG filter: none
        for _ in range(width):
            rows.extend(bytes([rng.randrange(256)]) * 3)

    def chunk(kind, data):
        return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))

    png = (b'\x89PNG\r\n\x1a\n' +
           chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)) +
           chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b''))
    target = ROOT / 'libfprint/tests/vfs5011/capture.png'
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(png)


def run(args):
    subprocess.run(args, cwd=ROOT, check=True)


def main():
    if os.geteuid() == 0:
        raise SystemExit('Build as an ordinary user; installation is a separate step.')
    verify_all()
    for tool in ('gcc', 'g++', 'make', 'ld', 'objcopy', 'pkg-config', 'meson', 'ninja',
                 'glib-mkenums', 'glib-genmarshal'):
        if not shutil.which(tool):
            raise SystemExit('Missing build tool: ' + tool + '. See README.md.')
    run(['pkg-config', '--exists', 'gusb', 'gudev-1.0', 'glib-2.0', 'gio-unix-2.0',
         'gobject-2.0', 'gmodule-2.0', 'cairo', 'openssl', 'zlib'])
    # Retain the pilot's private libgusb2 layout and bind it in the manifest.
    libdir = Path(subprocess.check_output(['pkg-config', '--variable=libdir', 'gusb'], text=True).strip())
    library = libdir / 'libgusb.so.2.0.10'
    if not library.is_file():
        raise SystemExit('This pilot requires libgusb.so.2.0.10 (tested: libgusb 0.4.9).')
    target = ROOT / 'linux-driver/build-tools/root/usr/lib/libgusb.so.2.0.10'
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(library, target)
    for directory in ('native-probe', 'native-probe/factory-probe', 'native-probe/engine-probe'):
        run(['make', '-C', directory])
    synthetic_fixture()
    build = ROOT / 'libfprint/build-engine'
    options = ['-Ddrivers=goodix_chicago_engine', '-Dintrospection=false', '-Ddoc=false',
               '-Dgtk-examples=false', '-Dinstalled-tests=false', '-Dudev_rules=disabled',
               '-Dudev_hwdb=disabled']
    run(['meson', 'setup', *(['--reconfigure'] if (build / 'build.ninja').exists() else []),
         str(build), str(ROOT / 'libfprint'), *options])
    run([sys.executable, 'native-sgx/build_engine_service.py'])
    run([sys.executable, 'scripts/test.py'])
    print(json.dumps({'built': True, 'hardware_used': False,
                      'manifest': 'native-sgx/engine-service-build/build.json'}))


if __name__ == '__main__':
    main()
