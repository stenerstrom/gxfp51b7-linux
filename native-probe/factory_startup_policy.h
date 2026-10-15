/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_FACTORY_STARTUP_POLICY_H
#define GXFP_FACTORY_STARTUP_POLICY_H

/* Shared by native_probe and the offline startup regression. The original
 * factory module requires its 512-frame session. The separate original-Engine
 * module intentionally permits exactly one baseline acquisition instead.
 */
#if defined(GXFP_ORIGINAL_ENGINE_IDENTITY) && !defined(GXFP_ORIGINAL_ENGINE_SERVICE)
#define GXFP_FACTORY_REQUIRED_CAPTURE_LIMIT 1U
#else
#define GXFP_FACTORY_REQUIRED_CAPTURE_LIMIT 512U
#endif

struct gxfp_factory_startup_options {
	bool run, driver_startup, observe_mailbox, map_mailbox;
	bool iova_layout_verified, tls_stream;
	bool reset_first, chip_id_only, mcu_state, pmk_hash_metadata;
	bool tls_hello_metadata, scan_mailbox_candidates, key_metadata;
	bool wake_first, ec_f2_only;
	unsigned int capture_limit;
};

static inline bool gxfp_factory_startup_valid(const struct gxfp_factory_startup_options *options)
{
	return options->run && options->driver_startup && options->observe_mailbox &&
		options->map_mailbox && options->iova_layout_verified && options->tls_stream &&
		options->capture_limit == GXFP_FACTORY_REQUIRED_CAPTURE_LIMIT &&
		!options->reset_first && !options->chip_id_only && !options->mcu_state &&
		!options->pmk_hash_metadata && !options->tls_hello_metadata &&
		!options->scan_mailbox_candidates && !options->key_metadata &&
		!options->wake_first && !options->ec_f2_only;
}
#endif
