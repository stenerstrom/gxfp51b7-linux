/* ChicagoHS source packet: original image CRC, independent of TLS/UART CRC. */
#ifndef GXFP_CHICAGO_CRC_H
#define GXFP_CHICAGO_CRC_H
static inline unsigned int chicago_crc32(const unsigned char *data, unsigned int length)
{
	unsigned int crc = 0xffffffffU, i, bit;
	for (i = 0; i < length; i++) {
		crc ^= (unsigned int)data[i] << 24;
		for (bit = 0; bit < 8; bit++)
			crc = (crc << 1) ^ ((crc & 0x80000000U) ? 0x04c11db7U : 0);
	}
	return crc;
}
static inline int chicago_packet_valid(const unsigned char *data, unsigned int length)
{
	unsigned int expected;
	if (length != 10564) return 0;
	expected = ((unsigned int)data[length - 2] << 24) |
		   ((unsigned int)data[length - 1] << 16) |
		   ((unsigned int)data[length - 4] << 8) | data[length - 3];
	return chicago_crc32(data, length - 4) == expected;
}
#endif
