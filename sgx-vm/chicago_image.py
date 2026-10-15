"""Decode the original ChicagoHS source-image API, with no file writes.

Format evidence is the unchanged WBDI enclave's ChicagoHUDataRegroup at
0x180003a70..0x180005617 and CRC routines at 0x180003a00/0x1800016a0.
The 10560-byte source-size assumption must also pass physical verification.
"""
from array import array

WIDTH, HEIGHT = 80, 64
SOURCE_STRIDE = 132
SOURCE_BYTES = WIDTH * SOURCE_STRIDE
PACKET_BYTES = SOURCE_BYTES + 4


def _crc_table():
    values = []
    for byte in range(256):
        value = byte << 24
        for _ in range(8):
            value = ((value << 1) ^ (0x04C11DB7 if value & 0x80000000 else 0)) & 0xFFFFFFFF
        values.append(value)
    return tuple(values)


_CRC_TABLE = _crc_table()


def crc32_mpeg2(data):
    value = 0xFFFFFFFF
    for byte in data:
        value = _CRC_TABLE[(value >> 24) ^ byte] ^ ((value << 8) & 0xFFFFFFFF)
    return value


def decode_source_packet(packet):
    """Return 80x64 row-major u16 pixels only after length and CRC checks."""
    if len(packet) != PACKET_BYTES:
        raise ValueError('Unexpected ChicagoHS source-image size')
    expected = (packet[-2] << 24) | (packet[-1] << 16) | (packet[-4] << 8) | packet[-3]
    if crc32_mpeg2(memoryview(packet)[:-4]) != expected:
        raise ValueError('ChicagoHS image CRC mismatch')
    pixels = array('H', [0]) * (WIDTH * HEIGHT)
    for column in range(WIDTH):
        start = column * SOURCE_STRIDE
        for row in range(0, HEIGHT, 4):
            offset = start + row * 3 // 2
            b0, b1, b2, b3, b4, b5 = packet[offset:offset + 6]
            pixels[row * WIDTH + column] = ((b0 & 15) << 8) | b1
            pixels[(row + 1) * WIDTH + column] = (b3 << 4) | (b0 >> 4)
            pixels[(row + 2) * WIDTH + column] = ((b5 & 15) << 8) | b2
            pixels[(row + 3) * WIDTH + column] = (b4 << 4) | (b5 >> 4)
    return pixels
