#!/usr/bin/env python3
"""Offline SGX signature inspection. Does not load or execute driver code.

Layouts: Intel SDK 2.25 common/inc/internal/arch.h. The SGX SIGSTRUCT is
architectural; PE metadata outside that structure is not treated as ELF.
RSA verification authenticates the signed metadata, not the PE page layout.
"""
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'windows-driver-1.1.151.18/extracted/source'
SIG_HEADER = bytes.fromhex('06000000e100000000000100')


def inspect_enclave(path):
    data = path.read_bytes()
    offsets = [m.start() for m in re.finditer(re.escape(SIG_HEADER), data)]
    if len(offsets) != 1:
        raise ValueError(f'{path}: expected one SIGSTRUCT, found {len(offsets)}')
    offset = offsets[0]
    css = data[offset:offset + 1808]
    if len(css) != 1808:
        raise ValueError('Truncated SIGSTRUCT')
    modulus = css[128:512]
    exponent = int.from_bytes(css[512:516], 'little')
    signature = int.from_bytes(css[516:900], 'little')
    n = int.from_bytes(modulus, 'little')
    if n.bit_length() != 3072 or exponent not in (3, 65537) or signature >= n:
        raise ValueError('Invalid RSA parameters')
    digest = hashlib.sha256(css[:128] + css[900:1028]).digest()
    tail = bytes.fromhex('3031300d060960864801650304020105000420') + digest
    expected = b'\x00\x01' + b'\xff' * (384 - len(tail) - 3) + b'\x00' + tail
    valid = pow(signature, exponent, n).to_bytes(384, 'big') == expected
    attrs = struct.unpack_from('<Q', css, 928)[0]
    return {
        'file': str(path.relative_to(ROOT)),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sigstruct_file_offset': hex(offset),
        'signature_valid': valid,
        'mrsigner': hashlib.sha256(modulus).hexdigest(),
        'mrenclave': css[960:992].hex(),
        'attributes': hex(attrs),
        'debug': bool(attrs & 2),
        'product_id': struct.unpack_from('<H', css, 1024)[0],
        'svn': struct.unpack_from('<H', css, 1026)[0],
    }


def der_integer(raw):
    raw = raw.lstrip(b'\x00') or b'\x00'
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return b'\x02' + bytes([len(raw)]) + raw


def verify_ec(pub, signature, payload):
    # P-256 X/Y and ECDSA R/S are stored as big-endian 32-byte values.
    if len(pub) != 64 or len(signature) != 64:
        raise ValueError('Invalid P-256 field lengths')
    spki = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d03010703420004') + pub
    ints = der_integer(signature[:32]) + der_integer(signature[32:])
    sig = b'\x30' + bytes([len(ints)]) + ints
    with tempfile.TemporaryDirectory(prefix='gxfp-sgx-') as tmp:
        tmp = Path(tmp)
        (tmp / 'key.der').write_bytes(spki)
        (tmp / 'sig.der').write_bytes(sig)
        (tmp / 'data').write_bytes(payload)
        p = subprocess.run(['openssl', 'dgst', '-sha256', '-keyform', 'DER',
                            '-verify', str(tmp / 'key.der'), '-signature',
                            str(tmp / 'sig.der'), str(tmp / 'data')],
                           capture_output=True, text=True)
        return p.returncode == 0


def inspect_whitelist(path, enclaves):
    data = path.read_bytes()
    header = struct.unpack_from('>4H2I', data, 136)
    if len(data) != 136 + 16 + 32 * header[5] + 64:
        raise ValueError('Whitelist length does not match count')
    root_src = (ROOT / 'intel-sgx-sdk/psw/ae/data/constants/linux/wl_pub.hh').read_text()
    key_source = root_src.split('g_wl_root_pubkey =', 1)[1]
    root_le = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})', key_source))
    if len(root_le) != 64:
        raise ValueError('Cannot parse Intel root key')
    root_be = root_le[:32][::-1] + root_le[32:][::-1]
    entries = [data[i:i + 32].hex() for i in range(152, len(data) - 64, 32)]
    return {
        'file': str(path.relative_to(ROOT)),
        'provider_signature_valid_against_intel_linux_root':
            verify_ec(root_be, data[72:136], data[:72]),
        'whitelist_signature_valid': verify_ec(data[8:72], data[-64:], data[136:-64]),
        'launch_enclave_product_id': header[3],
        'linux_launch_enclave_product_id': 32,
        'product_id_matches_linux': header[3] == 32,
        'whitelist_version': header[4],
        'entry_count': header[5],
        'wildcard_signer': '00' * 32 in entries,
        'signers_present': {e['mrsigner']: e['mrsigner'] in entries for e in enclaves},
    }


if __name__ == '__main__':
    enclaves = [inspect_enclave(p) for p in sorted(SOURCE.rglob('*.signed.dll'))]
    result = {'enclaves': enclaves,
              'windows_whitelist': inspect_whitelist(SOURCE / 'sgx_white_list_cert.bin', enclaves),
              'linux_whitelist': inspect_whitelist(
                  ROOT / 'intel-sgx-sdk/psw/ae/data/prebuilt/white_list_cert_to_be_verify.bin', enclaves),
              'intel_linux_launch_enclave': inspect_enclave(
                  ROOT / 'tools/sgx-prebuilt/psw/ae/data/prebuilt/libsgx_le.signed.so'),
              'limitations': ['No enclave executed', 'PE measurement not reconstructed',
                              'No authentication or fingerprint capture tested']}
    print(json.dumps(result, indent=2))
    signed_lists_valid = all(
        result[key]['provider_signature_valid_against_intel_linux_root'] and
        result[key]['whitelist_signature_valid']
        for key in ('windows_whitelist', 'linux_whitelist'))
    if (len(enclaves) != 4 or not all(e['signature_valid'] for e in enclaves) or
            not signed_lists_valid or not result['intel_linux_launch_enclave']['signature_valid']):
        raise SystemExit(1)
