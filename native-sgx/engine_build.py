"""Validate the isolated original Engine candidate and its public dependencies."""
import hashlib
import json
from pathlib import Path
import re

PROJECT = Path(__file__).resolve().parents[1]
BUILD_RELATIVE = 'native-sgx/engine-service-build'
ENGINE_SHA256 = '2bc1648bcc06c9f163d7c4bde62b8ecd145d22ad3941da7dd9fa4504bc3b175b'
ORIGINAL = 'windows-driver-1.1.151.18/extracted/source/'
INTEL = 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10/'
EXPECTED_CHECKS = frozenset({'base_loader', 'kernel', 'worker', 'test_engine_service_action',
    'test_engine_service_runner', 'test_engine_metadata', 'test_startup_factory',
    'test_startup_baseline', 'test_startup_service', 'python', 'libfprint', 'libfprint_tests'})
REQUIRED_FILES = frozenset({
    'intel-sgx-sdk/psw/ae/data/constants/linux/wl_pub.hh',
    'scripts/build.py', 'scripts/import_vendor.py', 'scripts/test.py',
    'vendor-assets.json',
    'native-sgx/test_worker_identity.py',
    'native-sgx/install_engine_candidate.py', 'native-sgx/check_engine_candidate.py',
    'native-sgx/gxfp51b7-engine-backend.service', 'native-sgx/fprintd-engine.conf',
    'native-sgx/test_install_engine_candidate.py',
    'native-sgx/ENGINE_CANDIDATE.md',
    'native-sgx/engine_build.py', 'native-sgx/build_engine_service.py',
    'native-sgx/engine_backend.py', 'native-sgx/engine_reader.py',
    'native-sgx/engine_v2_protocol.py', 'native-sgx/engine_v2_protocol.h',
    'native-sgx/engine_service_runner.c', 'native-sgx/engine_service_action.h',
    'native-sgx/engine_service_contract.h', 'native-sgx/engine_baseline_runner.c',
    'native-sgx/engine_pair_runner.c', 'native-sgx/engine_init_runner.c',
    'native-sgx/kvm_runner.c', 'native-sgx/vm_guest.S',
    'native-sgx/engine_app_contract.h', 'native-sgx/engine_pair_launch.h',
    'native-sgx/engine_dh_contract.h', 'native-sgx/engine_image_contract.h',
    'native-sgx/engine_calibration_store.h', 'native-sgx/engine_baseline_probe.h',
    'native-sgx/engine_baseline_acquisition.h', 'native-sgx/wbdi_image_contract.h',
    'native-sgx/persistent_reader.py', 'native-sgx/service_reader.py',
    'native-sgx/fprint_backend.py', 'native-sgx/fprint_protocol.py',
    'native-sgx/run_trial.py', 'native-sgx/sealed_input.py',
    'native-sgx/transport_server.py',
    'sgx-vm/tls_bridge.py', 'sgx-vm/sealed_bridge.py',
    'sgx-vm/chicago_image.py', 'sgx-vm/chicago_crc.h',
    'analysis/btf_iova_layout.py',
    'native-probe/gxfp51b7_sealed.ko', 'native-probe/gxfp51b7_sealed.c',
    'native-probe/gxfp51b7_native.c', 'native-probe/factory_startup_policy.h',
    'native-probe/engine_identity.h', 'native-probe/engine_metadata.h',
    'native-probe/tls_stream.h', 'native-probe/chicago_factory_config.h',
    'native-probe/chicago_factory_bus.h',
    'native-probe/engine-service/gxfp51b7_engine_service.ko',
    'native-probe/engine-service/gxfp51b7_engine_service.c',
    'native-probe/engine-service/Makefile',
    BUILD_RELATIVE + '/engine_service_runner', BUILD_RELATIVE + '/engine.plan',
    BUILD_RELATIVE + '/wbdi.plan', BUILD_RELATIVE + '/intel-le.plan',
    ORIGINAL + 'Engine_Enclave_3.02.00.signed.dll',
    ORIGINAL + 'WBDI_Enclave.signed.dll', ORIGINAL + 'sgx_white_list_cert.bin',
    INTEL + 'le_prod_css.bin', INTEL + 'le.signed.dll',
    'libfprint/build-engine/libfprint/libfprint-2.so.2.0.0',
    'libfprint/libfprint/drivers/goodix_chicago_engine.c',
    'libfprint/libfprint/drivers/goodix_chicago_engine.h',
    'libfprint/libfprint/drivers/goodix_chicago_engine_print.c',
    'libfprint/libfprint/meson.build', 'libfprint/meson.build',
    'libfprint/tests/meson.build', 'libfprint/tests/test-goodix-chicago-engine.c',
    'linux-driver/build-tools/root/usr/lib/libgusb.so.2.0.10',
    'native-sgx/build_engine_trial.py', 'native-sgx/prepare_engine_trial.py',
    'native-sgx/pe_layout.py', 'analysis/verify_sgx.py',
    'native-sgx/run_engine_trial.py', 'native-sgx/run_engine_baseline_trial.py',
    'native-sgx/test_engine_sensor_identity.py', 'native-sgx/test_persistent_reader.py',
    'native-sgx/test_worker_cleanup.py', 'native-sgx/test_engine_baseline_launcher.py',
    BUILD_RELATIVE + '/vm_guest_blob.o', BUILD_RELATIVE + '/vm_guest.bin',
})


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def verify_build(project=None):
    root = (Path(project) if project is not None else PROJECT).resolve(strict=True)
    manifest = json.loads((root / BUILD_RELATIVE / 'build.json').read_text())
    if (manifest.get('schema') != 1 or manifest.get('probe') != 'original-engine-service' or
            manifest.get('protocol') != 2 or manifest.get('profile') != 12 or
            manifest.get('engine_sha256') != ENGINE_SHA256 or
            manifest.get('template_max_bytes') != 4 * 1024 * 1024 or
            manifest.get('template_min_bytes') != 0x255 or
            manifest.get('capture_limit') != 512 or manifest.get('session_limit_seconds') != 1200 or
            not isinstance(manifest.get('kernel'), str) or not manifest['kernel'] or
            manifest.get('adaptive_update_persisted') is not False or
            manifest.get('requires_empty_start') is not True):
        raise ValueError('Unexpected original Engine candidate identity')
    files = manifest.get('checked_files')
    if not isinstance(files, dict) or not REQUIRED_FILES.issubset(files):
        raise ValueError('Incomplete original Engine candidate dependency manifest')
    for relative, expected in files.items():
        if (not isinstance(relative, str) or Path(relative).is_absolute() or
                '..' in Path(relative).parts or not isinstance(expected, str) or
                not re.fullmatch('[0-9a-f]{64}', expected)):
            raise ValueError('Invalid original Engine manifest entry')
        path = root / relative
        if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
            raise ValueError('Original Engine dependency escapes its release')
        if digest(path) != expected:
            raise ValueError('Original Engine candidate changed: ' + relative)
    if files[ORIGINAL + 'Engine_Enclave_3.02.00.signed.dll'] != ENGINE_SHA256:
        raise ValueError('Unexpected original Engine binary')
    checks = manifest.get('checks')
    if not isinstance(checks, dict) or not EXPECTED_CHECKS.issubset(checks) or any(
            not isinstance(check, dict) or check.get('exit_code') != 0 for check in checks.values()):
        raise ValueError('Original Engine candidate checks are incomplete')
    return manifest


if __name__ == '__main__':
    verified = verify_build()
    print(json.dumps({'verified': True, 'files': len(verified['checked_files']), 'hardware_used': False}))
