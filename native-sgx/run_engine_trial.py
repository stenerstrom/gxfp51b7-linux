#!/usr/bin/env python3
"""Check or launch the isolated original-Engine startup probe.

--check is entirely offline. Launching requires local Polkit authentication
only to open SGX EPC; the worker runs after permanent privilege drop.
No reader, BIOS container, fingerprint template, or login setting is accessed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BUILD = HERE / 'engine-feasibility-build'
INTEL = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
ORIGINAL = PROJECT / 'windows-driver-1.1.151.18/extracted/source'


def verify_build():
    manifest = json.loads((BUILD / 'probe-build.json').read_text())
    if (manifest.get('schema') != 3 or manifest.get('application_ecalls') != [1, 2, 3] or
            manifest.get('pair_ecalls') != {'engine': [42, 43, 44, 45, 46, 47],
                                            'wbdi': [62, 63, 66, 67, 68, 69]}):
        raise ValueError('Unexpected probe scope')
    files = manifest.get('checked_files', {})
    required = {
        'native-sgx/engine-feasibility-build/engine_init_runner',
        'native-sgx/engine-feasibility-build/engine.plan',
        'native-sgx/engine-feasibility-build/intel-le.plan',
        'native-sgx/engine_init_runner.c', 'native-sgx/run_engine_trial.py',
        'native-sgx/engine_app_contract.h',
        'native-sgx/engine_pair_runner.c', 'native-sgx/engine_pair_launch.h',
        'native-sgx/engine_dh_contract.h', 'native-sgx/test_engine_pair_runner.c',
        'native-sgx/test_engine_pair_launch.c', 'native-sgx/test_engine_dh_contract.c',
        'native-sgx/engine-feasibility-build/engine_pair_runner',
        'native-sgx/engine-feasibility-build/wbdi.plan',
        'native-sgx/kvm_runner.c', 'native-sgx/vm_guest.S',
        'native-sgx/run_trial.py', 'native-sgx/fprint_protocol.py',
        'native-sgx/build_engine_trial.py', 'native-sgx/prepare_engine_trial.py',
        'native-sgx/pe_layout.py', 'native-sgx/test_engine_init_runner.c',
        'analysis/verify_sgx.py', 'sgx-vm/chicago_crc.h',
        'native-sgx/engine-feasibility-build/vm_guest.bin',
        'windows-driver-1.1.151.18/extracted/source/Engine_Enclave_3.02.00.signed.dll',
        'windows-driver-1.1.151.18/extracted/source/WBDI_Enclave.signed.dll',
        'windows-driver-1.1.151.18/extracted/source/sgx_white_list_cert.bin',
        str((INTEL / 'le_prod_css.bin').relative_to(PROJECT)),
        str((INTEL / 'le.signed.dll').relative_to(PROJECT)),
    }
    if not required.issubset(files):
        raise ValueError('Incomplete probe manifest')
    for relative, expected in files.items():
        path = PROJECT / relative
        if Path(relative).is_absolute() or not path.resolve().is_relative_to(PROJECT):
            raise ValueError('Manifest path outside project')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Probe build changed: ' + relative)
    return manifest


def runner_arguments(epc_fd, application=False, pair=False):
    if pair:
        return [str(BUILD / 'engine_pair_runner'), str(epc_fd),
                str(BUILD / 'intel-le.plan'), str(INTEL / 'le_prod_css.bin'),
                str(BUILD / 'wbdi.plan'), str(BUILD / 'engine.plan'),
                str(ORIGINAL / 'sgx_white_list_cert.bin')]
    args = [str(BUILD / 'engine_init_runner'), str(epc_fd),
            str(BUILD / 'intel-le.plan'), str(INTEL / 'le_prod_css.bin'),
            str(BUILD / 'engine.plan'), str(ORIGINAL / 'sgx_white_list_cert.bin')]
    return args + ['application'] if application else args


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--application', action='store_true',
                        help='Exercise original Attach, overlay configuration, and Detach.')
    mode.add_argument('--pair', action='store_true',
                      help='Exercise legitimate original WBDI-to-Engine local attestation.')
    options = parser.parse_args()
    verify_build()
    if options.check:
        print(json.dumps({'build_verified': True,
                          'scope': 'original_pair_dh' if options.pair else
                                   'engine_application_lifecycle' if options.application else 'engine_runtime_init',
                          'application_ecalls': [1, 2, 3] if options.application else [],
                          'hardware_used': False}))
        return
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise SystemExit('Launch through pkexec as the UID1000 desktop owner; use --check for offline validation.')
    for name, expected in (('sys_vendor', 'HUAWEI'), ('product_name', 'MACHC-WAX9')):
        if Path('/sys/class/dmi/id', name).read_text().strip() != expected:
            raise SystemExit('Unexpected computer')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    from run_trial import drop_privileges
    epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
    try:
        os.set_inheritable(epc_fd, True)
        drop_privileges()
        args = runner_arguments(epc_fd, options.application, options.pair)
        os.execve(args[0], args, {'PATH': '/usr/bin'})
    finally:
        os.close(epc_fd)


if __name__ == '__main__':
    main()
