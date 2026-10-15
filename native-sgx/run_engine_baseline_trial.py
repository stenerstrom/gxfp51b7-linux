#!/usr/bin/env python3
"""Check or launch the isolated original-Engine empty-baseline probe.

--check only hashes public build inputs. Launching requires local Polkit
authentication and an empty reader. The root parent obtains the original
encrypted BIOS container in sealed RAM and owns the existing bounded sensor
transport. The permanently unprivileged worker loads the original enclaves,
performs their legitimate local attestation, and initializes one baseline.
No image, calibration object, or template is written to persistent storage.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

import run_engine_trial

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
BUILD = HERE / 'engine-feasibility-build'
INTEL = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
ORIGINAL = PROJECT / 'windows-driver-1.1.151.18/extracted/source'

# The base manifest already binds the enclave images, plans, generic loader,
# launch helpers and assembly. Bind that manifest as well as this additional
# worker, its contracts, and every project-local import on this transport path.
# Kernel sources are provenance; the separately hashed .ko files are executed.
BASELINE_REQUIRED_FILES = frozenset({
    'native-probe/factory_startup_policy.h',
    'native-probe/test_factory_startup_policy.c',
    'native-sgx/engine-feasibility-build/probe-build.json',
    'native-sgx/engine-feasibility-build/engine_baseline_runner',
    'native-sgx/engine_baseline_runner.c',
    'native-sgx/engine_baseline_acquisition.h',
    'native-sgx/run_engine_baseline_trial.py',
    'native-sgx/test_engine_baseline_launcher.py',
    'native-sgx/test_engine_sensor_identity.py',
    'native-sgx/engine_baseline_probe.h',
    'native-sgx/test_engine_baseline_probe.c',
    'native-sgx/engine_image_contract.h',
    'native-sgx/test_engine_image_contract.c',
    'native-sgx/engine_calibration_store.h',
    'native-sgx/test_engine_calibration_store.c',
    'native-sgx/wbdi_image_contract.h',
    'native-sgx/test_wbdi_image_contract.c',
    'native-sgx/run_trial.py',
    'native-sgx/test_worker_cleanup.py',
    'native-sgx/fprint_protocol.py',
    'native-sgx/fprint_backend.py',
    'native-sgx/transport_server.py',
    'native-sgx/sealed_input.py',
    'sgx-vm/tls_bridge.py',
    'sgx-vm/sealed_bridge.py',
    'sgx-vm/chicago_image.py',
    'analysis/btf_iova_layout.py',
    'native-probe/gxfp51b7_sealed.ko',
    'native-probe/engine-probe/gxfp51b7_engine.ko',
    'native-probe/engine-probe/gxfp51b7_engine.c',
    'native-probe/engine-probe/Makefile',
    'native-probe/engine-probe/test_engine_identity.c',
    'native-probe/test_chicago_factory_bus.c',
    'native-probe/engine_identity.h',
    'native-probe/gxfp51b7_native.c',
    'native-probe/gxfp51b7_sealed.c',
    'native-probe/Makefile',
    'native-probe/frame.h',
    'native-probe/chicago_control_snapshot.h',
    'native-probe/blob.h',
    'native-probe/tls_hello.h',
    'native-probe/chicago_factory_bus.h',
    'native-probe/tls_stream.h',
    'native-probe/chicago_otp_query.h',
    'native-probe/chicago_config.h',
    'native-probe/chicago_factory_config.h',
    'native-probe/chicago_otp.h',
})


def verify_baseline_build():
    """Validate the base probe and the dedicated baseline dependency closure."""
    run_engine_trial.verify_build()
    manifest = json.loads((BUILD / 'baseline-build.json').read_text())
    if (manifest.get('schema') != 1 or
            manifest.get('probe') != 'original-engine-baseline'):
        raise ValueError('Unexpected baseline probe scope')
    files = manifest.get('checked_files')
    if not isinstance(files, dict) or not BASELINE_REQUIRED_FILES.issubset(files):
        raise ValueError('Incomplete baseline probe manifest')
    for relative, expected in files.items():
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError('Invalid baseline manifest entry')
        path = PROJECT / relative
        if Path(relative).is_absolute() or not path.resolve().is_relative_to(PROJECT):
            raise ValueError('Baseline manifest path outside project')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Baseline probe build changed: ' + relative)
    return manifest


def runner_arguments(epc_fd, sealed_fd, transport_fd, capture):
    """Match run_tls_trial's factory interface without changing its defaults."""
    if capture is not True or min(epc_fd, sealed_fd, transport_fd) < 0:
        raise ValueError('Baseline probe requires capture and all three descriptors')
    return [str(BUILD / 'engine_baseline_runner'), str(epc_fd),
            str(BUILD / 'intel-le.plan'), str(INTEL / 'le_prod_css.bin'),
            str(BUILD / 'wbdi.plan'), str(BUILD / 'engine.plan'),
            str(ORIGINAL / 'sgx_white_list_cert.bin'), str(sealed_fd),
            str(transport_fd)]


def _service_command(action, unit, timeout):
    """Use fixed local units; suppress command output and retain bounded errors."""
    try:
        result = subprocess.run(['/usr/bin/systemctl', action, unit],
                                capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Fingerprint service ' + action + ' exceeded its deadline') from None
    if result.returncode:
        raise RuntimeError('Fingerprint service ' + action + ' failed')


def _service_state(unit):
    try:
        result = subprocess.run(['/usr/bin/systemctl', 'show', unit,
                                 '--property=ActiveState', '--value'],
                                capture_output=True, text=True, timeout=5, check=False)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Fingerprint service state check exceeded its deadline') from None
    if result.returncode or result.stdout.strip() not in ('active', 'inactive'):
        raise RuntimeError('Fingerprint service is not in a stable active/inactive state')
    return result.stdout.strip()


@contextlib.contextmanager
def quiesce_backend():
    """Temporarily stop an idle backend and restore only its original state.

    Fprintd can activate this service through its installed Requires= rule;
    the user must avoid fprintd commands during the single baseline probe.
    No masks or unit settings change. Restoring an active backend invokes its
    ordinary startup calibration, so the reader must remain empty until done.
    """
    if _service_state('fprintd.service') != 'inactive':
        raise RuntimeError('Fprintd is active; leave the current user operation untouched')
    was_active = _service_state('gxfp51b7-backend.service') == 'active'
    restore = False
    failure = None
    try:
        if was_active:
            restore = True
            # Installed TimeoutStopSec=55 and TimeoutStartSec=120 leave a
            # small margin for systemctl communication and state reporting.
            _service_command('stop', 'gxfp51b7-backend.service', 65)
        if _service_state('gxfp51b7-backend.service') != 'inactive':
            raise RuntimeError('Fingerprint backend did not become inactive')
        if _service_state('fprintd.service') != 'inactive':
            raise RuntimeError('Fprintd became active before the baseline probe')
        print('baseline_backend_quiesced=1 restore_required=' + str(int(restore)), flush=True)
        yield
    except BaseException as error:
        failure = error
        raise
    finally:
        if restore:
            restore_started = time.monotonic()
            try:
                _service_command('start', 'gxfp51b7-backend.service', 130)
                if _service_state('gxfp51b7-backend.service') != 'active':
                    raise RuntimeError('Fingerprint backend did not return to active state')
                print('baseline_backend_restored=1', flush=True)
            except BaseException as restore_error:
                if failure is not None:
                    raise BaseExceptionGroup('Baseline probe and backend restoration failed',
                                             [failure, restore_error]) from None
                raise
            finally:
                print('baseline_backend_restore_elapsed_seconds=' +
                      format(time.monotonic() - restore_started, '.3f'), flush=True)


def _interrupt_probe(signum, frame):
    raise KeyboardInterrupt('Original baseline probe interrupted')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true',
                        help='Verify public build inputs without device or BIOS access.')
    options = parser.parse_args(argv)
    verify_baseline_build()
    if options.check:
        print(json.dumps({'build_verified': True,
                          'scope': 'original-engine-baseline',
                          'hardware_used': False,
                          'bios_used': False,
                          'template_used': False}))
        return 0
    if os.geteuid() != 0 or os.environ.get('PKEXEC_UID') != '1000':
        raise SystemExit('Launch through pkexec as the UID1000 desktop owner; use --check for offline validation.')
    for name, expected in (('sys_vendor', 'HUAWEI'), ('product_name', 'MACHC-WAX9')):
        if Path('/sys/class/dmi/id', name).read_text().strip() != expected:
            raise SystemExit('Unexpected computer')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    # Importing and calling the BIOS adapter is deliberately after --check,
    # local authentication checks and the machine-identity check.
    from sealed_input import create_sealed_input
    from run_trial import run_tls_trial
    previous_terminate = signal.signal(signal.SIGTERM, _interrupt_probe)
    try:
        with quiesce_backend():
            epc_fd = sealed_fd = -1
            try:
                epc_fd = os.open('/dev/sgx_vepc', os.O_RDWR | os.O_CLOEXEC)
                os.set_inheritable(epc_fd, True)
                sealed_fd = create_sealed_input()
                # run_tls_trial owns both descriptors on success and on exceptions.
                worker_epc, worker_sealed = epc_fd, sealed_fd
                epc_fd = sealed_fd = -1
                trial_started = time.monotonic()
                try:
                    return run_tls_trial(worker_epc, worker_sealed, capture=True,
                                         image_consumer=None, runner_factory=runner_arguments,
                                         allow_sensor_identity=True)
                finally:
                    print('baseline_native_trial_elapsed_seconds=' +
                          format(time.monotonic() - trial_started, '.3f'), flush=True)
            finally:
                for fd in (epc_fd, sealed_fd):
                    if fd >= 0:
                        os.close(fd)
    finally:
        signal.signal(signal.SIGTERM, previous_terminate)


if __name__ == '__main__':
    raise SystemExit(main())
