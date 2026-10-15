/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_ENGINE_METADATA_H
#define GXFP_ENGINE_METADATA_H

/* Versioned RAM-only SensorID/FDT parameters. No additional OTP transaction.
 * The caller supplies u8, bool, memcpy and memzero_explicit. Wire integers
 * are little endian; no C struct padding is part of the interface.
 */
#define GXFP_ENGINE_METADATA_SIZE 24U
static inline bool gxfp_engine_metadata_encode(u8 *out,
		const struct gxfp_engine_identity *identity,
		const struct chicago_factory_calibration *factory,
		bool started, bool negotiated)
{
	memzero_explicit(out, GXFP_ENGINE_METADATA_SIZE);
	if (!gxfp_engine_identity_available(identity, started, negotiated) ||
	    !factory->timing_valid || !factory->tcode)
		return false;
	out[0] = 1;
	out[2] = GXFP_ENGINE_METADATA_SIZE;
	memcpy(out + 4, identity->bytes, GXFP_ENGINE_IDENTITY_SIZE);
	out[20] = factory->tcode & 255;
	out[21] = factory->tcode >> 8;
	out[22] = factory->threshold;
	out[23] = 1; /* Already validated factory calibration. */
	return true;
}
#endif
