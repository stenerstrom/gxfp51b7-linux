# SPDX-License-Identifier: MPL-2.0
# Layout algorithm adapted from Fortanix, Inc.'s isgx-pe2sgx.rs and
# WINTEL-SGX-ABI.md (rust-sgx, revision efd09bcb5ac037d9a80e7bdce85d8547f0da392c).
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. https://mozilla.org/MPL/2.0/
"""Reconstruct a signed Windows SGX image without executing Windows code.

Supports the PE64 metadata 1.1/1.2/1.3 layout used by the local Goodix
enclaves and Intel's Windows Launch Enclave. The PE TLS directory also
supports TLS templates merged into .rdata, absent in the old converter.
No BIOS data, sensor data or launch token is read by this module.
"""
from dataclasses import dataclass
import hashlib
import struct

PAGE = 4096
MAGIC = 0x86A80294635D0E4C
REG = 0x200
TCS = 0x100


def align_page(value):
    return (value + PAGE - 1) & -PAGE


@dataclass(frozen=True)
class Page:
    offset: int
    flags: int
    measured: bool
    data: bytes


@dataclass(frozen=True)
class Section:
    name: bytes
    size: int
    rva: int
    raw_size: int
    raw_offset: int
    characteristics: int


class Layout:
    def __init__(self, data):
        if not isinstance(data, bytes) or not 512 <= len(data) <= 16 * 1024 * 1024:
            raise ValueError('Invalid input size')
        self.data = data
        self.pages = []
        self._parse()
        self._build()

    def read(self, offset, size):
        if offset < 0 or size < 0 or offset + size > len(self.data):
            raise ValueError('PE file range out of bounds')
        return self.data[offset:offset + size]

    def unpack(self, fmt, offset):
        return struct.unpack(fmt, self.read(offset, struct.calcsize(fmt)))

    def file_offset(self, rva, size=1):
        for section in self.sections:
            if (section.rva <= rva and
                    rva + size <= section.rva + section.raw_size):
                return section.raw_offset + rva - section.rva
        if 0 <= rva and rva + size <= self.header_size:
            return rva
        raise ValueError('RVA is not backed by file data')

    def rva_read(self, rva, size):
        return self.read(self.file_offset(rva, size), size)

    def directory(self, index):
        return self.unpack('<II', self.optional + 112 + 8 * index)

    def _parse(self):
        if self.read(0, 2) != b'MZ':
            raise ValueError('Missing DOS header')
        pe, = self.unpack('<I', 0x3c)
        if self.read(pe, 4) != b'PE\0\0':
            raise ValueError('Missing PE header')
        machine, count, _, _, _, optsize, _ = self.unpack('<HHIIIHH', pe + 4)
        self.optional = pe + 24
        if machine != 0x8664 or self.unpack('<H', self.optional)[0] != 0x20b:
            raise ValueError('Only x86-64 PE32+ is supported')
        if not 1 <= count <= 96 or optsize < 240:
            raise ValueError('Invalid PE headers')
        self.image_base, = self.unpack('<Q', self.optional + 24)
        section_align, = self.unpack('<I', self.optional + 32)
        self.header_size, = self.unpack('<I', self.optional + 60)
        directories, = self.unpack('<I', self.optional + 108)
        if section_align != PAGE or directories != 16 or self.header_size > PAGE:
            raise ValueError('Unsupported PE alignment or directories')
        self.sections = []
        end = align_page(self.header_size)
        for index in range(count):
            fields = self.unpack('<8sIIIIIIHHI', self.optional + optsize + index * 40)
            section = Section(fields[0].rstrip(b'\0'), *fields[1:5], fields[9])
            if section.rva % PAGE or section.rva < end or not section.size:
                raise ValueError('Unaligned or overlapping section')
            self.read(section.raw_offset, section.raw_size)
            end = section.rva + align_page(section.size)
            self.sections.append(section)
        metadata = [s for s in self.sections if s.name == b'sgxmeta']
        if len(metadata) != 1:
            raise ValueError('Expected exactly one SGX metadata section')
        self.metadata_offset = metadata[0].raw_offset
        fields = self.unpack('<QQ9IQQ', self.metadata_offset)
        (magic, version, size, self.threads, self.tls_field, self.nssa,
         self.ssa_size, self.stack_size, self.heap_size, xsave, misc,
         self.attributes, self.xfrm) = fields
        if magic != MAGIC or version not in (0x100000001, 0x100000002, 0x100000003):
            raise ValueError('Unsupported SGX metadata')
        self.version = version
        if not 1876 <= size <= metadata[0].raw_size:
            raise ValueError('Truncated SGX metadata')
        self.extended_signature = 0
        if version == 0x100000003:
            if size != 2660:
                raise ValueError('Unsupported metadata 1.3 extension')
            self.extended_signature, = self.unpack('<I', self.metadata_offset + 1876)
            if self.extended_signature not in (0, 1):
                raise ValueError('Unsupported extended signature flag')
        if (not 1 <= self.threads <= 32 or not 1 <= self.nssa <= 4 or
                self.ssa_size != 1 or xsave != 0xa48 or misc != 0 or
                self.tls_field not in (0, 1) or
                not PAGE <= self.stack_size <= 4 * 1024 * 1024 or
                not PAGE <= self.heap_size <= 16 * 1024 * 1024):
            raise ValueError('Unsupported SGX memory parameters')
        self.sigstruct = self.read(self.metadata_offset + 68, 1808)
        if self.sigstruct[:12] != bytes.fromhex('06000000e100000000000100'):
            raise ValueError('Missing SIGSTRUCT')
        self.expected_hash = self.sigstruct[960:992]
        tls_rva, tls_dir_size = self.directory(9)
        if tls_dir_size != 40:
            raise ValueError('Invalid PE64 TLS directory')
        tls = struct.unpack('<QQQQII', self.rva_read(tls_rva, 40))
        self.tls_rva = tls[0] - self.image_base
        self.tls_raw_size = tls[1] - tls[0]
        if not 112 <= self.tls_raw_size <= 16 * PAGE or tls[4] > 16 * PAGE:
            raise ValueError('Invalid TLS template')
        self.tls_size = align_page(self.tls_raw_size + tls[4])
        self.tls_template = bytearray(self.rva_read(self.tls_rva, self.tls_raw_size))
        export_rva, export_size = self.directory(0)
        exports = struct.unpack('<IIHHIIIIIII', self.rva_read(export_rva, 40))
        function_count, name_count, functions, names, ordinals = exports[6:11]
        if function_count > 4096 or name_count > function_count:
            raise ValueError('Invalid export table')
        self.entry = None
        for index in range(name_count):
            name_rva, = struct.unpack('<I', self.rva_read(names + 4 * index, 4))
            name_offset = self.file_offset(name_rva)
            name = self.read(name_offset, min(64, len(self.data) - name_offset)).split(b'\0', 1)[0]
            if name == b'enclave_entry':
                ordinal, = struct.unpack('<H', self.rva_read(ordinals + 2 * index, 2))
                if ordinal >= function_count:
                    raise ValueError('Invalid entry ordinal')
                self.entry, = struct.unpack('<I', self.rva_read(functions + 4 * ordinal, 4))
        if self.entry is None or export_rva <= self.entry < export_rva + export_size:
            raise ValueError('Missing or forwarded enclave_entry')
        self.reloc_pages = set()
        reloc_rva, reloc_size = self.directory(5)
        relocs = self.rva_read(reloc_rva, reloc_size)
        pos = 0
        while pos < len(relocs):
            if len(relocs) - pos < 8:
                raise ValueError('Truncated relocation block')
            rva, size = struct.unpack_from('<II', relocs, pos)
            if size < 8 or size % 2 or pos + size > len(relocs) or rva % PAGE:
                raise ValueError('Invalid relocation block')
            self.reloc_pages.add(rva // PAGE)
            pos += size
        self.heap_offset = end
        self.first_tcs = end + align_page(self.heap_size) + 0x10000
        self.thread_stride = (PAGE + self.tls_size + 0x10000 +
                              self.nssa * self.ssa_size * PAGE + 0x10000 +
                              align_page(self.stack_size))
        self.enclave_size = 1 << (self.first_tcs + self.threads * self.thread_stride - 1).bit_length()
        if self.enclave_size > 128 * 1024 * 1024:
            raise ValueError('Enclave exceeds the runner memory bound')

    def add_pages(self, offset, size, flags, data=None, fill=0, measured=True):
        for pos in range(0, align_page(size), PAGE):
            chunk = (data[pos:pos + PAGE] if data is not None else b'')
            chunk += bytes([fill]) * (PAGE - len(chunk))
            page_flags = flags
            if (offset + pos) // PAGE in self.reloc_pages:
                page_flags |= 2
            self.pages.append(Page(offset + pos, page_flags, measured, chunk))

    def _build(self):
        ssa = PAGE + self.tls_size + 0x10000
        bottom = ssa + self.nssa * self.ssa_size * PAGE + 0x10000
        top = bottom + align_page(self.stack_size)
        for off, value in ((8, top), (16, top), (24, bottom), (32, ssa),
                           (40, ssa + 0xf48), (48, PAGE),
                           (64, self.heap_offset), (72, self.enclave_size), (88, 0x1030)):
            struct.pack_into('<Q', self.tls_template, off, value)
        self.tls_template[56] = self.tls_field
        # Intel Windows uRTS 2.30, RVA 0x4c142..0x4c14b, copies this flag
        # into TLS byte 0x3a. Without it the signed LE measurement differs.
        self.tls_template[58] = self.extended_signature
        struct.pack_into('<II', self.tls_template, 96, 1, align_page(self.heap_size))
        header = bytearray(self.read(0, self.header_size))
        struct.pack_into('<I', header, self.optional + 64, 0)
        struct.pack_into('<II', header, self.optional + 112 + 8 * 4, 0, 0)
        self.add_pages(0, len(header), REG | 1, header)
        for section in self.sections:
            if section.name == b'sgxmeta':
                continue
            data = bytearray(self.read(section.raw_offset, section.raw_size))
            if section.rva <= self.tls_rva < section.rva + section.raw_size:
                pos = self.tls_rva - section.rva
                data[pos:pos + self.tls_raw_size] = self.tls_template
            flags = REG
            for characteristic, bit in ((0x40000000, 1), (0x80000000, 2), (0x20000000, 4)):
                if section.characteristics & characteristic:
                    flags |= bit
            self.add_pages(section.rva, section.size, flags, data)
        self.add_pages(self.heap_offset, self.heap_size, REG | 3, measured=False)
        for index in range(self.threads):
            offset = self.first_tcs + index * self.thread_stride
            tcs = bytearray(PAGE)
            struct.pack_into('<QQQIIQQQQII', tcs, 0, 0, 0, offset + ssa, 0,
                             self.nssa, self.entry, 0, offset + PAGE,
                             offset + PAGE, 0xfff, 0xfff)
            self.add_pages(offset, PAGE, TCS, tcs)
            self.add_pages(offset + PAGE, self.tls_size, REG | 3)
            self.add_pages(offset + ssa, self.nssa * self.ssa_size * PAGE, REG | 3)
            self.add_pages(offset + bottom, self.stack_size, REG | 3, fill=0xcc)
        offsets = [p.offset for p in self.pages]
        if offsets != sorted(set(offsets)):
            raise ValueError('Duplicate or unordered EPC pages')

    def measure(self):
        digest = hashlib.sha256()
        digest.update(struct.pack('<8sIQ44x', b'ECREATE\0', self.ssa_size, self.enclave_size))
        for page in self.pages:
            digest.update(struct.pack('<8sQQ40x', b'EADD\0\0\0\0', page.offset, page.flags))
            if page.measured:
                for offset in range(0, PAGE, 256):
                    digest.update(struct.pack('<8sQ48x', b'EEXTEND\0', page.offset + offset))
                    digest.update(page.data[offset:offset + 256])
        return digest.digest()

    def summary(self):
        measured = self.measure()
        return {'metadata_version': hex(self.version), 'threads': self.threads,
                'ssa_frame_pages': self.ssa_size, 'enclave_bytes': self.enclave_size,
                'loaded_pages': len(self.pages), 'measured_pages': sum(p.measured for p in self.pages),
                'first_tcs_rva': hex(self.first_tcs), 'entry_rva': hex(self.entry),
                'mrenclave': measured.hex(), 'signed_mrenclave': self.expected_hash.hex(),
                'measurement_matches': measured == self.expected_hash}

    def write_plan(self, path):
        """Write only reconstructed public enclave code, never live SGX state."""
        if self.measure() != self.expected_hash:
            raise ValueError('Refusing a plan with a mismatched measurement')
        header = struct.pack('<8s7Q', b'B7SGX001', self.enclave_size, self.ssa_size,
                             self.first_tcs, self.attributes, 3, len(self.pages), self.entry)
        with path.open('wb') as output:
            output.write(header + self.sigstruct + bytes(PAGE - len(header) - len(self.sigstruct)))
            for page in self.pages:
                output.write(struct.pack('<QQQ8x', page.offset, page.flags, int(page.measured)))
                output.write(page.data)


if __name__ == '__main__':
    import json
    from pathlib import Path
    import sys
    for arg in sys.argv[1:]:
        layout = Layout(Path(arg).read_bytes())
        print(json.dumps({'file': arg, **layout.summary()}, indent=2))
        if layout.measure() != layout.expected_hash:
            raise SystemExit(1)
