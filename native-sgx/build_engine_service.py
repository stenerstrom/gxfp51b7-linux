#!/usr/bin/env python3
"""Build/check an isolated original Engine candidate; never touch hardware."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

from engine_build import PROJECT, BUILD_RELATIVE, REQUIRED_FILES, ENGINE_SHA256, digest, verify_build

HERE = PROJECT / 'native-sgx'
BUILD = PROJECT / BUILD_RELATIVE
BASE = HERE / 'engine-feasibility-build'


def checked(args, name, cwd=BUILD, env=None):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True)
    (BUILD / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(f'{name} failed; inspect {BUILD / (name + ".log")}')
    return {'command': args, 'exit_code': 0}


def local_includes(files):
    """Bind transitively included project C files, not private runtime files."""
    pending = list(files)
    files = set(files)
    while pending:
        relative = pending.pop()
        path = PROJECT / relative
        if path.suffix not in ('.h', '.c', '.S'):
            continue
        for include in re.findall(r'^\s*#\s*include\s+"([^"]+)"', path.read_text(), re.M):
            child = (path.parent / include).resolve()
            if not child.is_file():
                # Generated libfprint headers are covered by the built library.
                continue
            if not child.is_relative_to(PROJECT):
                raise ValueError('Source dependency outside project')
            name = str(child.relative_to(PROJECT))
            if name not in files:
                files.add(name)
                pending.append(name)
    return files


def main():
    BUILD.mkdir(exist_ok=True)
    checks = {}
    preserved = {str(path.relative_to(PROJECT)): digest(path) for path in (
        PROJECT / 'native-probe/gxfp51b7_native.ko',
        PROJECT / 'native-probe/factory-probe/gxfp51b7_factory.ko',
        PROJECT / 'native-probe/engine-probe/gxfp51b7_engine.ko')}
    checks['base_loader'] = checked([sys.executable, str(HERE / 'build_engine_trial.py')], 'base-loader')
    for name in ('intel-le.plan', 'wbdi.plan', 'engine.plan', 'vm_guest_blob.o', 'vm_guest.bin'):
        shutil.copyfile(BASE / name, BUILD / name)
    checks['kernel'] = checked(['make', '-C', str(PROJECT / 'native-probe/engine-service')], 'kernel')
    common = ['gcc', '-Wall', '-Wextra', '-Werror', '-std=gnu11', '-Wl,-z,noexecstack']
    checks['worker'] = checked(common + ['-O2', '-o', 'engine_service_runner',
        str(HERE / 'engine_service_runner.c'), 'vm_guest_blob.o', '-lcrypto', '-lz'], 'worker')
    synthetic = common + ['-O1', '-g', '-fsanitize=undefined', '-fno-sanitize-recover=all']
    tests = {
        'test_engine_service_action': [str(HERE / 'test_engine_service_action.c')],
        'test_engine_service_runner': [str(HERE / 'test_engine_service_runner.c'), 'vm_guest_blob.o', '-lcrypto', '-lz'],
        'test_engine_metadata': [str(PROJECT / 'native-probe/engine-service/test_engine_metadata.c')],
    }
    for scope, flags in (('factory', []), ('baseline', ['-DGXFP_ORIGINAL_ENGINE_IDENTITY=1']),
                         ('service', ['-DGXFP_ORIGINAL_ENGINE_IDENTITY=1', '-DGXFP_ORIGINAL_ENGINE_SERVICE=1'])):
        tests['test_startup_' + scope] = [str(PROJECT / 'native-probe/test_factory_startup_policy.c'), *flags]
    for name, args in tests.items():
        checked(synthetic + ['-o', name, *args], name + '-build')
        checks[name] = checked([str(BUILD / name)], name)
    tests_python = ['test_install_engine_candidate', 'test_engine_build', 'test_engine_v2_protocol', 'test_engine_reader', 'test_engine_backend',
                    'test_engine_metadata_bridge', 'test_engine_sensor_identity',
                    'test_persistent_reader', 'test_worker_cleanup', 'test_engine_baseline_launcher', 'test_worker_identity']
    checks['python'] = checked([sys.executable, '-m', 'unittest', '-v', *tests_python], 'python', HERE)
    env = dict(os.environ)
    # scripts/build.py configures this isolated Engine-only library first.
    checks['libfprint'] = checked(['ninja', '-C', str(PROJECT / 'libfprint/build-engine')], 'libfprint', env=env)
    checks['libfprint_tests'] = checked(['meson', 'test', '-C', str(PROJECT / 'libfprint/build-engine'),
                                      '--suite', 'unit-tests', '--print-errorlogs'], 'libfprint-tests', env=env)
    for relative, expected in preserved.items():
        if digest(PROJECT / relative) != expected:
            raise RuntimeError('An existing kernel transport changed: ' + relative)
    files = local_includes(REQUIRED_FILES | {
        'native-sgx/test_engine_service_action.c', 'native-sgx/test_engine_service_runner.c',
        'native-sgx/test_engine_metadata_bridge.py', 'native-sgx/test_engine_v2_protocol.py',
        'native-sgx/test_engine_backend.py', 'native-sgx/test_engine_reader.py',
        'native-sgx/test_engine_build.py',
        'native-probe/engine-service/test_engine_metadata.c',
        'native-probe/test_factory_startup_policy.c',
    })
    # The base build records every signature/layout input and shared test source.
    # Include that provenance transitively, without installing private runtime data.
    base_manifest = json.loads((BASE / 'probe-build.json').read_text())
    files |= set(base_manifest['checked_files'])
    files.add('native-sgx/engine-feasibility-build/probe-build.json')
    files |= {str(p.relative_to(PROJECT)) for p in (PROJECT / 'intel-sgx-sdk/common/inc').rglob('*.h')}
    manifest = dict(schema=1, probe='original-engine-service', protocol=2, profile=12,
        engine_sha256=ENGINE_SHA256, kernel=os.uname().release, hardware_used_during_build=False,
        adaptive_update_persisted=False, requires_empty_start=True,
        template_max_bytes=4 * 1024 * 1024, template_min_bytes=0x255,
        capture_limit=512, session_limit_seconds=1200,
        checks=checks, preserved_transport_sha256=preserved,
        checked_files={name: digest(PROJECT / name) for name in sorted(files)})
    (BUILD / 'build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    verify_build()
    print(json.dumps({'built': True, 'verified': True, 'hardware_used': False,
                      'manifest': str(BUILD / 'build.json'), 'files': len(files)}))


if __name__ == '__main__':
    main()
