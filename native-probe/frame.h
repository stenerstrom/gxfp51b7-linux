/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_FRAME_H
#define GXFP_FRAME_H

/* Shared by the kernel probe and the host-side malformed-frame test. */
static inline unsigned int frame_length(const unsigned char *p,
				       unsigned int capacity)
{
	unsigned int n;
	if (capacity < 4 || ((p[0] & 0xf0) != 0xa0 && (p[0] & 0xf0) != 0xb0) ||
	    p[3] != (unsigned char)(p[0] + p[1] + p[2]))
		return 0;
	n = p[1] | ((unsigned int)p[2] << 8);
	return n >= 4 && n <= capacity - 4 ? n + 4 : 0;
}

static inline int frame_valid(const unsigned char *p, unsigned int n)
{
	unsigned int i, inner;
	unsigned char sum = 0;
	if (n < 8 || frame_length(p, n) != n || (p[0] & 0xf0) != 0xa0)
		return 0;
	inner = p[5] | ((unsigned int)p[6] << 8);
	if (inner < 1 || inner + 7 != n)
		return 0;
	for (i = 4; i < n; i++)
		sum += p[i];
	return sum == 0xaa;
}

/* OpenGoodixSPI #16 documents CHIP (0x90) replies as MSG (0xb0),
 * with the echoed command followed by a little-endian 16-bit chip ID.
 * Validate the whole frame before interpreting it; a generic ACK is not
 * evidence of a chip ID. The reported ID is not assumed for this machine.
 */
static inline int frame_chip_id(const unsigned char *p, unsigned int n,
				unsigned int *chip_id)
{
	if (!frame_valid(p, n) || n != 11 || p[4] != 0xb0 || p[7] != 0x90)
		return 0;
	*chip_id = p[8] | ((unsigned int)p[9] << 8);
	return 1;
}

/* Original ChipRegRead (0x18004cdfc) swaps each byte pair, then
 * init_FPSensor (0x18005d99c) builds a 24-bit ID from bytes 1, 2, 3.
 * This is a different transaction from the external empty-0x90 report.
 */
static inline int frame_register_chip_id(const unsigned char *p, unsigned int n,
					 unsigned int *chip_id)
{
	if (!frame_valid(p, n) || n != 12 || p[4] != 0x82)
		return 0;
	*chip_id = p[7] | ((unsigned int)p[10] << 8) |
		   ((unsigned int)p[9] << 16);
	return 1;
}

static inline unsigned int frame_u32le(const unsigned char *p)
{
	return p[0] | ((unsigned int)p[1] << 8) |
	       ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

/* Read-only operation 2 uses E4. Wire payload starts with status.
 * data_from_device (0x18005234d) prepends a four-byte length in software
 * for ProductionOperateKey; that length is not transmitted on the wire.
 */
static inline int frame_pmk_hash_result(const unsigned char *p, unsigned int n,
				      unsigned int *status,
				      const unsigned char **data, unsigned int *len)
{
	if (!frame_valid(p, n) || p[4] != 0xe4 || n < 9)
		return 0;
	*status = p[7];
	*data = p + 8;
	*len = n - 9;
	return 1;
}
#endif
