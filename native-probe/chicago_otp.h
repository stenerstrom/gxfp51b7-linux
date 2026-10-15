/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_CHICAGO_OTP_H
#define GXFP_CHICAGO_OTP_H

/* Own gfspi.dll 1.1.151.18: 1ca40, 2fb24, 2fd74, 2ffb0, 30180,
 * 3034c, 30578. No raw OTP or sensor identity is retained in the result. */
#define CHICAGO_OTP_FT_INFO 1U
#define CHICAGO_OTP_FT_DAC 2U
#define CHICAGO_OTP_MT_INFO 4U
#define CHICAGO_OTP_MT_DAC 8U
#define CHICAGO_OTP_REPAIRED 16U
#define CHICAGO_OTP_NONZERO 32U
#define CHICAGO_OTP_NONBLANK 64U
struct chicago_otp_result {
	unsigned int flags, selection;
	unsigned short dac[4];
};

static inline unsigned char chicago_crc8(const unsigned char *data, unsigned int n)
{
	unsigned int i, bit, crc = 0;
	for (i = 0; i < n; i++) {
		crc ^= data[i];
		for (bit = 0; bit < 8; bit++)
			crc = ((crc << 1) & 255U) ^ ((crc & 128U) ? 7U : 0U);
	}
	return (unsigned char)(crc ^ 255U);
}

static inline int chicago_otp_analyze(const unsigned char *otp, unsigned int length,
				      struct chicago_otp_result *out)
{
	unsigned char data[64], ft[19] = { 0 }, mt[27];
	unsigned int i, j, count = 0, different = 0, sum = 0, offset;
	unsigned int nonzero = 1, nonblank = 0;
	volatile unsigned char *erase;
	if (!out) return 0;
	out->flags = out->selection = 0;
	for (i = 0; i < 4; i++) out->dac[i] = 0;
	if (!otp || length != 64) return 0;
	for (i = 0; i < 64; i++) data[i] = otp[i];
	for (i = 0; i < 9; i++) ft[i] = data[0x0b + i];
	ft[9] = data[0x1c];
	for (i = 0; i < 4; i++) ft[10 + i] = data[0x32 + i];
	ft[14] = data[0x38]; /* Original CRC includes four initialized zeros. */
	for (i = 0; i < 8; i++) mt[i] = data[0x14 + i];
	for (i = 0; i < 7; i++) mt[8 + i] = data[0x1d + i];
	for (i = 0; i < 10; i++) mt[15 + i] = data[0x28 + i];
	mt[25] = data[0x36]; mt[26] = data[0x37];
	if (chicago_crc8(ft, 19) == data[0x3d]) out->flags |= CHICAGO_OTP_FT_INFO;
	if (chicago_crc8(mt, 27) == data[0x3f]) out->flags |= CHICAGO_OTP_MT_INFO;
	if (data[0x32] && data[0x33] && data[0x34] && data[0x35] &&
	    chicago_crc8(data + 0x32, 4) == data[0x3e]) out->flags |= CHICAGO_OTP_FT_DAC;
	if (data[0x2e] && data[0x2f] && data[0x30] && data[0x31] &&
	    chicago_crc8(data + 0x2e, 4) == data[0x16]) out->flags |= CHICAGO_OTP_MT_DAC;
	if (out->flags & (CHICAGO_OTP_FT_INFO | CHICAGO_OTP_FT_DAC)) out->selection = 1;
	else if (out->flags & (CHICAGO_OTP_MT_INFO | CHICAGO_OTP_MT_DAC)) out->selection = 2;
	else {
		for (i = 0; i < 4; i++) {
			if (data[0x2e + i] == data[0x32 + i]) {
				count++;
				sum += data[0x2e + i];
			} else different = i;
		}
		if (count >= 3) {
			out->selection = 3;
			if (count == 3) {
				data[0x2e + different] = data[0x32 + different] = sum / 3;
				out->flags |= CHICAGO_OTP_REPAIRED;
			}
		}
	}
	offset = out->selection == 2 ? 0x2e : 0x32;
	for (i = 0; i < 4; i++) {
		nonzero &= data[offset + i] != 0;
		nonblank |= data[offset + i] != 255;
	}
	if (out->selection && nonzero) out->flags |= CHICAGO_OTP_NONZERO;
	if (out->selection && nonblank) out->flags |= CHICAGO_OTP_NONBLANK;
	if (out->selection && nonzero && nonblank) {
		out->dac[0] = ((unsigned short)data[offset] << 4) | 8;
		for (i = 1; i < 4; i++) out->dac[i] = data[offset + i];
	}
	/* Use volatile stores also in standalone diagnostic tests. */
	for (j = 0; j < 3; j++) {
		erase = j == 0 ? data : j == 1 ? ft : mt;
		for (i = 0; i < (j == 0 ? 64U : j == 1 ? 19U : 27U); i++) erase[i] = 0;
	}
	return 1;
}
#endif
