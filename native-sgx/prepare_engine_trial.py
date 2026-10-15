#!/usr/bin/env python3
"""Prepare the exact signed Engine load plan using public files only.

This is an offline feasibility check, not a launcher. It does not open SGX,
KVM, the sensor, firmware interfaces, templates, or private key containers.
The existing acquisition plans and runner remain untouched.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parent
sys.path.insert(0, str(PROJECT / 'analysis'))
from verify_sgx import inspect_enclave, inspect_whitelist
from pe_layout import Layout, PAGE, TCS

SOURCE = PROJECT / 'windows-driver-1.1.151.18/extracted/source'
INTEL = PROJECT / 'sgx-vm/intel/Intel_SGX_DCAP_for_Windows/psw/WindowsServer2019_Windows10'
BUILD = HERE / 'engine-feasibility-build'
REPORT = PROJECT / 'analysis/engine-native-feasibility-2026-10-14/load-feasibility.json'
ENGINE_HASH = '2bc1648bcc06c9f163d7c4bde62b8ecd145d22ad3941da7dd9fa4504bc3b175b'
INTEL_SIGNER = 'acb77012053e05a63d413b8bbae8fb6c5d73b3f2996d91c43bbbf90959c0f8d4'


def require(condition, message):
    if not condition:
        raise ValueError(message)


def relative(path):
    return str(path.relative_to(PROJECT))


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def inspect_plan(path, expected):
    """Independently replay the serialized ECREATE/EADD/EEXTEND transcript."""
    raw = path.read_bytes()
    magic, size, ssa, tcs, attrs, xfrm, count, entry = struct.unpack_from('<8s7Q', raw)
    require(magic == b'B7SGX001', 'Unexpected plan format')
    require(len(raw) == PAGE + count * (PAGE + 32), 'Plan size mismatch')
    require(raw[64:1872] == expected.sigstruct, 'Plan SIGSTRUCT differs from the original')
    require(not any(raw[1872:PAGE]), 'Nonzero plan header padding')
    require((size, ssa, tcs, attrs, xfrm, count, entry) ==
            (expected.enclave_size, expected.ssa_size, expected.first_tcs,
             expected.attributes, 3, len(expected.pages), expected.entry),
            'Plan metadata differs from reconstructed image')
    digest = hashlib.sha256(struct.pack('<8sIQ44x', b'ECREATE\0', ssa, size))
    previous = -1
    tcs_offsets = []
    for index in range(count):
        start = PAGE + index * (PAGE + 32)
        offset, flags, measured, reserved = struct.unpack_from('<4Q', raw, start)
        data = raw[start + 32:start + 32 + PAGE]
        require(previous < offset < size and offset % PAGE == 0,
                'Unordered or out-of-range plan page')
        require(measured in (0, 1) and reserved == 0, 'Invalid plan page metadata')
        require(flags == TCS or flags & ~7 == 0x200, 'Invalid plan SECINFO flags')
        canonical = expected.pages[index]
        require((offset, flags, measured, data) ==
                (canonical.offset, canonical.flags, int(canonical.measured), canonical.data),
                'Plan page differs from canonical reconstruction, including unmeasured initialization')
        if flags == TCS:
            tcs_offsets.append(offset)
        digest.update(struct.pack('<8sQQ40x', b'EADD\0\0\0\0', offset, flags))
        if measured:
            for block in range(0, PAGE, 256):
                digest.update(struct.pack('<8sQ48x', b'EEXTEND\0', offset + block))
                digest.update(data[block:block + 256])
        previous = offset
    require(digest.digest() == expected.expected_hash, 'Serialized plan measurement mismatch')
    require(tcs_offsets == [expected.first_tcs + i * expected.thread_stride
                            for i in range(expected.threads)], 'Unexpected TCS population')
    signed_xfrm = struct.unpack_from('<Q', expected.sigstruct, 936)[0]
    xfrm_mask = struct.unpack_from('<Q', expected.sigstruct, 952)[0]
    signed_attrs = struct.unpack_from('<Q', expected.sigstruct, 928)[0]
    attrs_mask = struct.unpack_from('<Q', expected.sigstruct, 944)[0]
    require((xfrm & xfrm_mask) == (signed_xfrm & xfrm_mask), 'XFRM violates signature mask')
    require((attrs & attrs_mask) == (signed_attrs & attrs_mask), 'Attributes violate signature mask')
    return {'path': relative(path), 'sha256': sha256(path), 'bytes': len(raw),
            'serialized_measurement_matches': True, 'tcs_count': len(tcs_offsets),
            'runtime_xfrm': hex(xfrm), 'metadata_xfrm': hex(expected.xfrm),
            'signed_xfrm': hex(signed_xfrm), 'signed_xfrm_mask': hex(xfrm_mask),
            'attributes_and_xfrm_satisfy_signature_masks': True}


def image_details(path):
    signature = inspect_enclave(path)
    require(signature['signature_valid'] and not signature['debug'],
            'Expected an intact production enclave signature')
    layout = Layout(path.read_bytes())
    require(layout.measure() == layout.expected_hash, 'Signed measurement mismatch')
    pages = {page.offset: page for page in layout.pages}
    entry_page = pages.get(layout.entry & -PAGE)
    require(entry_page is not None and entry_page.flags & 4, 'Entry is not executable')
    thread_records = []
    for index in range(layout.threads):
        offset = layout.first_tcs + index * layout.thread_stride
        page = pages[offset]
        fields = struct.unpack_from('<QQQIIQQQQII', page.data)
        require(page.flags == TCS and page.measured, 'TCS must be a measured TCS page')
        require(fields[4] == layout.nssa and fields[5] == layout.entry,
                'TCS entry or SSA count mismatch')
        require(fields[7] == fields[8] == offset + PAGE, 'Unexpected TLS bases')
        require(fields[2] in pages and offset + PAGE in pages, 'Missing SSA or TLS page')
        thread_records.append({'tcs_rva': hex(offset), 'ssa_rva': hex(fields[2]),
                               'tls_rva': hex(fields[7]), 'entry_rva': hex(fields[5]),
                               'nssa': fields[4]})
    return layout, {**signature, **layout.summary(),
                    'heap_bytes': layout.heap_size, 'stack_bytes_per_thread': layout.stack_size,
                    'tls_template_rva': hex(layout.tls_rva),
                    'tls_template_bytes': layout.tls_raw_size,
                    'tls_bytes_per_thread': layout.tls_size,
                    'thread_stride_bytes': layout.thread_stride, 'threads_detail': thread_records,
                    'epc_pages_including_secs': len(layout.pages) + 1}


def main():
    engine_path = SOURCE / 'Engine_Enclave_3.02.00.signed.dll'
    require(sha256(engine_path) == ENGINE_HASH, 'Engine does not match the previously audited package')
    paths = {'engine': engine_path, 'wbdi': SOURCE / 'WBDI_Enclave.signed.dll',
             'intel_le': INTEL / 'le.signed.dll'}
    images, layouts = {}, {}
    for name, path in paths.items():
        layouts[name], images[name] = image_details(path)
    production = inspect_enclave(INTEL / 'le_prod_css.bin')
    require(production['signature_valid'] and not production['debug'] and
            production['mrenclave'] == images['intel_le']['mrenclave'] and
            production['mrsigner'] == INTEL_SIGNER,
            'Intel production launch signature failed verification')
    whitelist = inspect_whitelist(SOURCE / 'sgx_white_list_cert.bin',
                                  [images['engine'], images['wbdi']])
    require(whitelist['provider_signature_valid_against_intel_linux_root'] and
            whitelist['whitelist_signature_valid'] and
            all(whitelist['signers_present'].values()) and
            whitelist['launch_enclave_product_id'] == production['product_id'],
            'Supplied signed launch authorization does not cover this Engine and launch enclave')

    runner = HERE / 'kvm_runner.c'
    runner_source = runner.read_text()
    # Fail if these audited bounds change rather than reporting stale assumptions.
    for literal in ('#define EPC_SIZE (32ULL << 20)', '#define EPC_BASE 0x10000000ULL',
                    'for (uint64_t i = 0; i < EPC_SIZE; i += PAGE) map_page(EPC_BASE + i, EPC_BASE + i, 7);',
                    '#define LE_BASE 0x40000000ULL',
                    '#define GOODIX_BASE 0x42000000ULL', 'h.size > (32ULL << 20)',
                    'if (pdpt_index > 1)', 'next_epc >= EPC_SIZE / PAGE',
                    'next_table + PAGE >= CONTROL', 'next_table = 0x20000',
                    '#define CONTROL 0x60000ULL', 'h.xfrm != 3'):
        require(literal in runner_source, 'Runner contract changed: ' + literal)
    epc_capacity = 32 * 1024 * 1024 // PAGE
    bounds = {}
    placements = {'intel_le': 0x40000000, 'wbdi': 0x42000000, 'engine': 0x44000000}
    for names, label in ((('intel_le', 'engine'), 'init_only'),
                         (('intel_le', 'wbdi', 'engine'), 'future_three_enclave')):
        epc_pages = sum(images[name]['epc_pages_including_secs'] for name in names)
        # setup_vm first maps the complete EPC physical aperture at an
        # identity address, independently of later enclave linear mappings.
        epc_identity_tables = set(range(0x10000000 >> 21, 0x12000000 >> 21))
        enclave_tables = set()
        ranges = []
        for name in names:
            layout = layouts[name]
            base = 0x42000000 if label == 'init_only' and name == 'engine' else placements[name]
            require(layout.enclave_size <= 32 * 1024 * 1024 and base % layout.enclave_size == 0,
                    'Runner image size or base alignment limit exceeded')
            require(base + layout.enclave_size <= 0x80000000, 'Runner page-table address limit exceeded')
            ranges.append((base, base + layout.enclave_size, name))
            enclave_tables.update((base + page.offset) >> 21 for page in layout.pages)
        ranges.sort()
        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), 'Image ranges overlap')
        mapped_tables = epc_identity_tables | enclave_tables
        require(epc_pages <= epc_capacity and len(mapped_tables) <= 63, 'Runner capacity exceeded')
        bounds[label] = {'epc_pages': epc_pages, 'epc_capacity_pages': epc_capacity,
                         'epc_headroom_pages': epc_capacity - epc_pages,
                         'epc_bytes': epc_pages * PAGE,
                         'page_table_pages': len(mapped_tables), 'page_table_capacity_pages': 63,
                         'epc_identity_page_table_pages': len(epc_identity_tables),
                         'enclave_page_table_pages': len(enclave_tables),
                         'ranges': [{'name': name, 'base': hex(start), 'end_exclusive': hex(end)}
                                    for start, end, name in ranges],
                         'offline_capacity_checks_pass': True}

    BUILD.mkdir(exist_ok=True)
    plan = BUILD / 'engine.plan'
    layouts['engine'].write_plan(plan)
    plan_report = inspect_plan(plan, layouts['engine'])
    protected_paths = [HERE / 'prepare_engine_trial.py', runner]
    result = {
        'schema': 1, 'purpose': 'Offline exact-Engine signature, measurement, layout, and runner feasibility',
        'engine_plan': plan_report, 'images': images,
        'intel_le_production_signature': production, 'vendor_whitelist': whitelist,
        'runner': {'path': relative(runner), 'sha256': sha256(runner), 'capacity': bounds,
                   'uses_hardware_sgx_in_os_free_kvm_guest': True,
                   'windows_os_or_windows_emulation_required_by_loader': False},
        'existing_read_only_artifacts': {relative(path): sha256(path) for path in protected_paths},
        'minimal_follow_up': [
            'Use a separate init-only runner; current main calls WBDI-specific ECALL 0x2d.',
            'Preserve existing authentic launch-enclave authorization and signed Engine bytes.',
            'Use Engine-specific application ECALL marshalling and OCALL dispatch, not the WBDI callback table.',
            'First separate EINIT, trusted-runtime initialization, application initialization, and close outcomes.',
            'Do not pass BIOS, sensor, DH-session, or template inputs to an init-only trial.',
            'A later WBDI-to-Engine session needs both enclaves in the same KVM/SGX context and separate addresses.',
        ],
        'limitations': [
            'No SGX or KVM device was opened; no enclave or vendor instruction was executed.',
            'Offline capacity does not establish currently available physical EPC or runtime compatibility.',
            'Metadata XFRM is 0xe7; the prepared plan uses signed-mask-compatible XFRM 3 like the existing loader.',
            'The signed whitelist covers the vendor signer but runtime launch authorization remains untested for Engine.',
            'Successful loading alone would not establish initialization, legitimate session handoff, enrollment, or recognition.',
        ],
        'hardware_access': False, 'source_binary_modified': False, 'production_files_modified': False,
    }
    REPORT.parent.mkdir(exist_ok=True)
    REPORT.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'report': relative(REPORT), 'engine_plan': plan_report,
                      'runner_capacity': bounds, 'hardware_access': False}, indent=2))


if __name__ == '__main__':
    main()
