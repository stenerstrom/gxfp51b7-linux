/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_ENGINE_IDENTITY_H
#define GXFP_ENGINE_IDENTITY_H

/* Original Engine SensorInfo[1:17] is OTP[0:16]. This opt-in cache only
 * receives an already validated factory reply; it performs no sensor I/O.
 * The including kernel or synthetic test supplies u8, bool, size_t, memcpy,
 * and memzero_explicit. No identity bytes belong in diagnostic output.
 */
#define GXFP_ENGINE_IDENTITY_SIZE 16
#define GXFP_ENGINE_OTP_SIZE 64
struct gxfp_engine_identity {
	u8 bytes[GXFP_ENGINE_IDENTITY_SIZE];
	bool valid;
};

static inline void gxfp_engine_identity_clear(struct gxfp_engine_identity *identity)
{
	memzero_explicit(identity, sizeof(*identity));
}

static inline bool gxfp_engine_identity_retain(struct gxfp_engine_identity *identity,
					      const u8 *otp, size_t length,
					      bool factory_reply_valid)
{
	u8 any = 0;
	size_t i;
	gxfp_engine_identity_clear(identity);
	if (!factory_reply_valid || !otp || length != GXFP_ENGINE_OTP_SIZE)
		return false;
	/* Original init_FPSensor rejects an entirely zero OTP reply. Do not
	 * invent additional restrictions on the first sixteen bytes alone. */
	for (i = 0; i < length; i++) any |= otp[i];
	if (!any) return false;
	memcpy(identity->bytes, otp, sizeof(identity->bytes));
	identity->valid = true;
	return true;
}

static inline bool gxfp_engine_identity_available(const struct gxfp_engine_identity *identity,
						 bool started, bool negotiation_done)
{
	return started && negotiation_done && identity->valid;
}
#endif
