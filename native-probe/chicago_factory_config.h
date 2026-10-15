/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_CHICAGO_FACTORY_CONFIG_H
#define GXFP_CHICAGO_FACTORY_CONFIG_H
#include "chicago_otp.h"
#include "chicago_config.h"

/* Own gfspi.dll: ChicagoHU_check_sensor 2e920, modify_image_tcode 1c66c,
 * modify_fdt_delta 1c200, modify_sensor_config 1c4c0. Values stay in RAM.
 * Timing requires the already verified MT information CRC as well as the
 * original redundant byte checks. No caller-supplied calibration values.
 */
struct chicago_factory_calibration {
	struct chicago_otp_result otp;
	unsigned short tcode;
	unsigned char threshold, fdt_offset;
	unsigned int timing_valid;
};

static inline int chicago_factory_derive(const unsigned char *data, unsigned int n,
					struct chicago_factory_calibration *out)
{
	unsigned int a, b, inverse, chosen = 0, raw_threshold, tcode;
	if (!out) return 0;
	out->tcode = out->threshold = out->fdt_offset = out->timing_valid = 0;
	if (!chicago_otp_analyze(data, n, &out->otp)) return 0;
	if (!(out->otp.flags & CHICAGO_OTP_NONZERO) ||
	    !(out->otp.flags & CHICAGO_OTP_NONBLANK) ||
	    !(out->otp.flags & CHICAGO_OTP_MT_INFO)) return 0;
	inverse = data[0x2b] ^ 255U;
	if (data[0x2a] && data[0x2a] == inverse) chosen = data[0x2a];
	else if (data[0x2d] && data[0x2d] == inverse) chosen = data[0x2d];
	else if (data[0x2a] && data[0x2a] == data[0x2d]) chosen = data[0x2a];
	if (!chosen || !data[0x2a]) return 0;
	/* The original validates either redundant byte, but calculates from 2a.
	 * Preserve that behavior rather than silently substituting byte 2d. */
	tcode = ((((unsigned int)data[0x2a] >> 4) + 1) << 4) + 0x40;
	raw_threshold = ((data[0x2a] & 15U) + 2) * 100;
	out->tcode = tcode;
	out->threshold = (unsigned char)(((raw_threshold * 256U / tcode) / 3U) >> 4);
	a = data[0x1b] & 3U;
	b = (data[0x1b] >> 4) & 3U;
	inverse = ((data[0x1b] ^ 255U) >> 2) & 3U;
	if (data[0x1b]) {
		if (a == b || a == inverse) out->fdt_offset = a;
		else if (b == inverse) out->fdt_offset = b;
	}
	out->timing_valid = 1;
	return 1;
}

static inline unsigned int chicago_factory_wire(unsigned char *frame, unsigned int capacity,
						unsigned char command, const unsigned char *data,
						unsigned int bytes)
{
	unsigned int i, length = bytes + 8;
	unsigned char sum = 0;
	if (!frame || !data || bytes > 256 || capacity < length) return 0;
	frame[0] = 0xa0; frame[1] = (unsigned char)(bytes + 4);
	frame[2] = (unsigned char)((bytes + 4) >> 8);
	frame[3] = (unsigned char)(frame[0] + frame[1] + frame[2]);
	frame[4] = command; frame[5] = (unsigned char)(bytes + 1);
	frame[6] = (unsigned char)((bytes + 1) >> 8);
	for (i = 0; i < bytes; i++) frame[i + 7] = data[i];
	for (i = 4; i < length - 1; i++) sum += frame[i];
	frame[length - 1] = (unsigned char)(0xaa - sum);
	return length;
}

/* Address list is fixed by ChicagoHUGetDac and our three config patches.
 * Registers carry only volatile analogue/scan settings, never flash or PMK. */
#define CHICAGO_FACTORY_REGISTERS 7U
static const unsigned short chicago_factory_addresses[CHICAGO_FACTORY_REGISTERS] = {
	0x0220, 0x0236, 0x0238, 0x023a, 0x005c, 0x0082, 0x0056,
};

static inline unsigned int chicago_factory_register_frame(unsigned char *frame,
						unsigned int capacity, unsigned int index,
						int write, unsigned short value)
{
	unsigned short address;
	unsigned char payload[5];
	if (index >= CHICAGO_FACTORY_REGISTERS || (write != 0 && write != 1)) return 0;
	address = chicago_factory_addresses[index];
	payload[0] = 0; payload[1] = (unsigned char)address;
	payload[2] = (unsigned char)(address >> 8);
	/* ChipRegRead takes a byte count; ChipRegWrite sends two value bytes. */
	payload[3] = write ? (unsigned char)value : 2;
	payload[4] = write ? (unsigned char)(value >> 8) : 0;
	return chicago_factory_wire(frame, capacity, write ? 0x80 : 0x82, payload, 5);
}

static inline unsigned int chicago_factory_dac_frame(unsigned char *frame, unsigned int capacity,
						   const unsigned short *dac)
{
	unsigned char payload[8];
	unsigned int i, result;
	volatile unsigned char *erase = payload;
	if (!dac) return 0;
	for (i = 0; i < 4; i++) {
		payload[2 * i] = (unsigned char)dac[i];
		payload[2 * i + 1] = (unsigned char)(dac[i] >> 8);
	}
	result = chicago_factory_wire(frame, capacity, 0x98, payload, 8);
	for (i = 0; i < 8; i++) erase[i] = 0;
	return result;
}

static inline int chicago_factory_patch(unsigned char *config, unsigned int offset_byte,
					unsigned short address, unsigned short value,
					int low_byte_only, int high_byte_only)
{
	unsigned int begin = config[offset_byte], bytes = config[offset_byte + 1], i, found = 0;
	if (begin < 17 || bytes % 4 || begin + bytes > 254) return 0;
	for (i = begin; i < begin + bytes; i += 4) {
		if ((config[i] | ((unsigned int)config[i + 1] << 8)) != address) continue;
		if (!high_byte_only) config[i + 2] = (unsigned char)value;
		if (!low_byte_only) config[i + 3] = (unsigned char)(value >> 8);
		found++;
	}
	return found == 1;
}

static inline unsigned int chicago_factory_config_frame(unsigned char *frame,
						unsigned int capacity,
						const struct chicago_factory_calibration *calibration)
{
	unsigned char config[256];
	unsigned int i, result = 0, sum = 0xa5a5;
	volatile unsigned char *erase = config;
	if (!frame || capacity < 264 || !calibration || !calibration->timing_valid ||
	    calibration->tcode < 80 || calibration->tcode > 320 || calibration->fdt_offset > 3)
		return 0;
	for (i = 0; i < 256; i++) config[i] = chicago_default_config[i];
	if (!chicago_factory_patch(config, 9, 0x005c, calibration->tcode, 0, 0) ||
	    !chicago_factory_patch(config, 5, 0x0082,
				  (unsigned short)calibration->threshold << 8, 0, 1)) goto done;
	if (calibration->fdt_offset && !chicago_factory_patch(config, 5, 0x0056,
							calibration->fdt_offset + 4, 1, 0)) goto done;
	for (i = 0; i < 254; i += 2) sum += config[i] | ((unsigned int)config[i + 1] << 8);
	sum = (0U - sum) & 65535U;
	config[254] = (unsigned char)sum; config[255] = (unsigned char)(sum >> 8);
	result = chicago_factory_wire(frame, capacity, 0x90, config, 256);
done:
	for (i = 0; i < 256; i++) erase[i] = 0;
	return result;
}
#endif
