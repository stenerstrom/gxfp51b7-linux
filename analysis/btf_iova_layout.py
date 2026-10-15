#!/usr/bin/env python3
"""Verify running kernel BTF before using its private DMA-cookie prefix."""
from pathlib import Path
import json
import struct


def verify_layout():
    data = Path('/sys/kernel/btf/vmlinux').read_bytes()
    magic, version, flags, hdr, toff, tlen, soff, slen = struct.unpack_from('<HBBIIIII', data)
    if magic != 0xeb9f or version != 1 or flags:
        raise ValueError('Unsupported BTF header')
    strings = data[hdr+soff:hdr+soff+slen]
    types = {}
    current, end, ident = hdr+toff, hdr+toff+tlen, 1
    strides = {0: 0, 1: 4, 2: 0, 3: 12, 4: None, 5: None,
               6: None, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0,
               12: 0, 13: None, 14: 4, 15: None, 16: 0,
               17: 4, 18: 0, 19: None}
    def name_at(off):
        return strings[off:strings.find(b'\0', off)].decode()
    while current < end:
        name, info, size = struct.unpack_from('<III', data, current)
        kind, count = (info >> 24) & 31, info & 65535
        stride = strides[kind]
        extra = stride if stride is not None else count * (8 if kind in (6, 13) else 12)
        record = {'name': name_at(name), 'kind': kind, 'size': size}
        if kind == 4 and record['name'] in ('iommu_dma_cookie', 'iova_domain'):
            record['members'] = [
                {'name': name_at(n), 'type': t, 'offset_bits': o}
                for n, t, o in (struct.unpack_from('<III', data, current+12+i*12)
                                for i in range(count))]
        types[ident] = record
        ident += 1
        current += 12 + extra
    matches = {r['name']: r for r in types.values() if 'members' in r}
    cookie, iovad = matches['iommu_dma_cookie'], matches['iova_domain']
    first = cookie['members'][0]
    if first['name'] != 'iovad' or first['offset_bits'] != 0 or \
            types[first['type']]['name'] != 'iova_domain':
        raise ValueError('DMA cookie prefix differs from the reviewed source')
    offsets = {m['name']: m['offset_bits'] for m in iovad['members']}
    # These values also have compile-time checks against this kernel's headers.
    if iovad['size'] != 128 or any(offsets.get(n) != bit for n, bit in
            {'granule': 256, 'start_pfn': 320, 'anchor': 512}.items()):
        raise ValueError('Unexpected iova_domain ABI')
    return {'kernel_dma_cookie_iovad_offset': 0, 'iova_domain_size': iovad['size'],
            'iova_member_offsets_bits': offsets, 'layout_verified': True}


if __name__ == '__main__':
    print(json.dumps(verify_layout(), indent=2))
