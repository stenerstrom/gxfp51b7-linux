#!/usr/bin/env python3
"""Run synthetic host, protocol, cleanup, and PAM tests without a reader."""
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    tests = sorted(p.stem for p in (ROOT / 'native-sgx').glob('test_*.py'))
    if not tests:
        raise RuntimeError('Missing synthetic host test sources')
    subprocess.run([sys.executable, '-m', 'unittest', '-v', *tests],
                   cwd=ROOT / 'native-sgx', check=True)
    subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
                    str(ROOT / 'authentication/pam_probe.c'), '-lpam',
                    '-o', str(ROOT / 'authentication/pam_probe')], check=True)
    subprocess.run([sys.executable, '-m', 'unittest', '-v', 'test_integrate_pam'],
                   cwd=ROOT / 'authentication', check=True)
    subprocess.run([sys.executable, '-m', 'unittest', '-v', 'test_packaging'],
                   cwd=ROOT / 'scripts', check=True)
    # Real C boundary code, undefined-behavior sanitizer, entirely synthetic input.
    with tempfile.TemporaryDirectory(prefix='gxfp-check-') as directory:
        sources = ['native-sgx/test_engine_service_action.c',
                   'native-probe/engine-service/test_engine_metadata.c',
                   'native-probe/test_frame.c', 'native-probe/test_blob.c',
                   'native-probe/test_tls_hello.c', 'native-probe/test_chicago_config.c',
                   'native-probe/test_chicago_factory_bus.c']
        for number, source in enumerate(sources):
            output = str(Path(directory) / str(number))
            subprocess.run(['gcc', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
                            '-fsanitize=undefined', '-fno-sanitize-recover=all',
                            str(ROOT / source), '-o', output], check=True)
            subprocess.run([output], check=True)


if __name__ == '__main__':
    main()
