#!/usr/bin/env python3
"""Pass the original encrypted BIOS container via a sealed, RAM-only FD.

This reads no plaintext key or fingerprint and leaves no kernel reader loaded.
"""
import fcntl
import os
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parent.parent


def create_sealed_input(report=None):
    """Return a sealed FD; let protocol callers route numeric diagnostics."""
    if os.geteuid() != 0 or not (os.environ.get('PKEXEC_UID') == '1000' or
                               os.environ.get('GXFP51B7_SERVICE') == '1'):
        raise RuntimeError('Encrypted BIOS read requires local pkexec authentication')
    sys.path.insert(0, str(PROJECT / 'sgx-vm'))
    from sealed_bridge import read_sealed_blob
    encrypted = read_sealed_blob()
    fd = -1
    try:
        fd = os.memfd_create('gxfp-encrypted-bios', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        written = 0
        while written < len(encrypted):
            count = os.write(fd, memoryview(encrypted)[written:])
            if count <= 0:
                raise RuntimeError('Incomplete RAM-only encrypted BIOS transfer')
            written += count
        os.lseek(fd, 0, os.SEEK_SET)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        os.set_inheritable(fd, True)
        message = ('encrypted_bios_ram_fd=1 bytes=' + str(len(encrypted)) +
                   ' temporary_bios_reader_unloaded=1 plaintext_key_export=0')
        if report is None:
            print(message, flush=True)
        else:
            report(message)
        result, fd = fd, -1
        return result
    finally:
        encrypted[:] = b'\0' * len(encrypted)
        if fd >= 0:
            os.close(fd)
