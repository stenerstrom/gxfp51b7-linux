#!/usr/bin/env python3
"""Build an isolated original-Engine startup probe; never access hardware."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BUILD = HERE / 'engine-feasibility-build'
REPORT = PROJECT / 'analysis/engine-native-feasibility-2026-10-14'
INTEL = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
ORIGINAL = PROJECT / 'windows-driver-1.1.151.18/extracted/source'
ENGINE_SHA256 = '2bc1648bcc06c9f163d7c4bde62b8ecd145d22ad3941da7dd9fa4504bc3b175b'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    BUILD.mkdir(exist_ok=True)
    REPORT.mkdir(exist_ok=True)
    if digest(ORIGINAL / 'Engine_Enclave_3.02.00.signed.dll') != ENGINE_SHA256:
        raise RuntimeError('Unexpected original Engine binary')
    subprocess.run([sys.executable, str(HERE / 'prepare_engine_trial.py')], check=True)
    from prepare_engine_trial import Layout, inspect_plan, image_details
    le_layout = Layout((INTEL / 'le.signed.dll').read_bytes())
    le_layout.write_plan(BUILD / 'intel-le.plan')
    le_plan_validation = inspect_plan(BUILD / 'intel-le.plan', le_layout)
    wbdi_layout, wbdi_identity = image_details(ORIGINAL / 'WBDI_Enclave.signed.dll')
    wbdi_layout.write_plan(BUILD / 'wbdi.plan')
    wbdi_plan_validation = inspect_plan(BUILD / 'wbdi.plan', wbdi_layout)
    commands = [
        ['gcc', '-c', '-o', 'vm_guest.o', str(HERE / 'vm_guest.S')],
        ['objcopy', '-O', 'binary', '-j', '.text', 'vm_guest.o', 'vm_guest.bin'],
        ['ld', '-r', '-z', 'noexecstack', '-b', 'binary', '-o', 'vm_guest_blob.o', 'vm_guest.bin'],
        ['gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
         '-Wl,-z,noexecstack', '-o', 'engine_init_runner',
         str(HERE / 'engine_init_runner.c'), 'vm_guest_blob.o', '-lcrypto', '-lz'],
        ['gcc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
         '-fsanitize=undefined', '-fno-sanitize-recover=all', '-Wl,-z,noexecstack',
         '-o', 'test_engine_init_runner', str(HERE / 'test_engine_init_runner.c'),
         'vm_guest_blob.o', '-lcrypto', '-lz'],
    ]
    commands.append(['gcc', '-O2', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
                     '-Wl,-z,noexecstack', '-o', 'engine_pair_runner',
                     str(HERE / 'engine_pair_runner.c'), 'vm_guest_blob.o', '-lcrypto', '-lz'])
    extra_tests = ('test_engine_pair_runner', 'test_engine_pair_launch', 'test_engine_dh_contract',
                   'test_engine_image_contract', 'test_engine_calibration_store', 'test_outside_stack')
    for name in extra_tests:
        commands.append(['gcc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
                         '-fsanitize=undefined', '-fno-sanitize-recover=all',
                         '-I' + str(PROJECT / 'intel-sgx-sdk/common/inc'), '-Wl,-z,noexecstack',
                         '-o', name, str(HERE / (name + '.c')),
                         'vm_guest_blob.o', '-lcrypto', '-lz'])
    commands.append(['gcc', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-std=gnu11',
                     '-fsanitize=undefined', '-fno-sanitize-recover=all',
                     '-DKVM_OUTSIDE_STACK_BOTTOM=0x180000ULL', '-DKVM_OUTSIDE_STACK_TOP=0x280000ULL',
                     '-Wl,-z,noexecstack', '-o', 'test_outside_stack_large',
                     str(HERE / 'test_outside_stack.c'), 'vm_guest_blob.o', '-lcrypto', '-lz'])
    for command in commands:
        subprocess.run(command, cwd=BUILD, check=True)
    check = subprocess.run([str(BUILD / 'test_engine_init_runner')],
                           text=True, capture_output=True)
    (BUILD / 'synthetic-test.log').write_text(check.stdout + check.stderr)
    if check.returncode:
        raise RuntimeError('Engine probe synthetic checks failed; see synthetic-test.log')
    test_results = {}
    for name in (*extra_tests, 'test_outside_stack_large'):
        args = [str(BUILD / name)]
        if name == 'test_engine_pair_launch':
            args.append(str(ORIGINAL / 'sgx_white_list_cert.bin'))
        trial = subprocess.run(args, text=True, capture_output=True)
        (BUILD / (name + '.log')).write_text(trial.stdout + trial.stderr)
        test_results[name] = trial.returncode
        if trial.returncode:
            raise RuntimeError(name + ' failed; inspect its build log')
    paths = [
        HERE / 'engine_init_runner.c', HERE / 'kvm_runner.c', HERE / 'vm_guest.S',
        HERE / 'run_engine_trial.py', HERE / 'run_trial.py',
        HERE / 'fprint_protocol.py', HERE / 'build_engine_trial.py',
        HERE / 'prepare_engine_trial.py', HERE / 'pe_layout.py',
        HERE / 'test_engine_init_runner.c',
        HERE / 'engine_app_contract.h',
        HERE / 'engine_pair_runner.c', HERE / 'engine_pair_launch.h',
        HERE / 'engine_dh_contract.h', HERE / 'test_engine_pair_runner.c',
        HERE / 'test_engine_pair_launch.c', HERE / 'test_engine_dh_contract.c',
        HERE / 'engine_image_contract.h', HERE / 'engine_calibration_store.h',
        HERE / 'test_engine_image_contract.c', HERE / 'test_engine_calibration_store.c',
        HERE / 'test_outside_stack.c',
        PROJECT / 'sgx-vm/chicago_crc.h', PROJECT / 'analysis/verify_sgx.py',
        ORIGINAL / 'Engine_Enclave_3.02.00.signed.dll',
        ORIGINAL / 'WBDI_Enclave.signed.dll',
        ORIGINAL / 'sgx_white_list_cert.bin', INTEL / 'le_prod_css.bin',
        INTEL / 'le.signed.dll',
        BUILD / 'engine.plan', BUILD / 'intel-le.plan', BUILD / 'engine_init_runner',
        BUILD / 'vm_guest.bin',
        BUILD / 'engine_pair_runner', BUILD / 'wbdi.plan',
    ]
    manifest = {
        'schema': 3,
        'purpose': 'Original Engine runtime, optional Attach/Detach, or original WBDI/Engine DH',
        'application_ecalls': [1, 2, 3],
        'pair_ecalls': {'engine': [42, 43, 44, 45, 46, 47], 'wbdi': [62, 63, 66, 67, 68, 69]},
        'hardware_used': False,
        'reader_used': False,
        'template_used': False,
        'synthetic_checks_exit': check.returncode,
        'intel_le_plan': le_plan_validation,
        'wbdi_plan': wbdi_plan_validation,
        'wbdi_identity': wbdi_identity,
        'pair_synthetic_checks': test_results,
        'commands': commands,
        'checked_files': {str(p.relative_to(PROJECT)): digest(p) for p in paths},
    }
    (BUILD / 'probe-build.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'built': True, 'scope': 'engine_runtime_application_and_paired_dh',
                      'manifest': str(BUILD / 'probe-build.json'), 'hardware_used': False}))


if __name__ == '__main__':
    main()
