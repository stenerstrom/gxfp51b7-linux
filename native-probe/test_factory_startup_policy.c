/* Exercise the actual native_probe factory startup policy in both builds.
 * These inputs are the complete option vectors used by TlsBridge, with all
 * unspecified module booleans at their real false defaults. No hardware. */
#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "factory_startup_policy.h"

int main(void)
{
    const struct gxfp_factory_startup_options baseline = {
        .run = true, .driver_startup = true, .observe_mailbox = true,
        .map_mailbox = true, .iova_layout_verified = true, .tls_stream = true,
        .capture_limit = 1,
    };
    struct gxfp_factory_startup_options factory = baseline;
    factory.capture_limit = 512;
    struct gxfp_factory_startup_options valid;
#if defined(GXFP_ORIGINAL_ENGINE_IDENTITY) && !defined(GXFP_ORIGINAL_ENGINE_SERVICE)
    /* The exact baseline launcher vector caused the original -EINVAL. */
    assert(gxfp_factory_startup_valid(&baseline));
    assert(!gxfp_factory_startup_valid(&factory));
    valid = baseline;
#else
    /* The existing factory module must still reject default capture_limit=1. */
    assert(!gxfp_factory_startup_valid(&baseline));
    assert(gxfp_factory_startup_valid(&factory));
    valid = factory;
#endif
    const size_t required[] = {
        offsetof(struct gxfp_factory_startup_options, run),
        offsetof(struct gxfp_factory_startup_options, driver_startup),
        offsetof(struct gxfp_factory_startup_options, observe_mailbox),
        offsetof(struct gxfp_factory_startup_options, map_mailbox),
        offsetof(struct gxfp_factory_startup_options, iova_layout_verified),
        offsetof(struct gxfp_factory_startup_options, tls_stream),
    };
    const size_t excluded[] = {
        offsetof(struct gxfp_factory_startup_options, reset_first),
        offsetof(struct gxfp_factory_startup_options, chip_id_only),
        offsetof(struct gxfp_factory_startup_options, mcu_state),
        offsetof(struct gxfp_factory_startup_options, pmk_hash_metadata),
        offsetof(struct gxfp_factory_startup_options, tls_hello_metadata),
        offsetof(struct gxfp_factory_startup_options, scan_mailbox_candidates),
        offsetof(struct gxfp_factory_startup_options, key_metadata),
        offsetof(struct gxfp_factory_startup_options, wake_first),
        offsetof(struct gxfp_factory_startup_options, ec_f2_only),
    };
    unsigned int rejected = 1;
    for (size_t i = 0; i < sizeof(required) / sizeof(required[0]); i++) {
        struct gxfp_factory_startup_options missing = valid;
        *(bool *)((unsigned char *)&missing + required[i]) = false;
        assert(!gxfp_factory_startup_valid(&missing));
        rejected++;
    }
    for (size_t i = 0; i < sizeof(excluded) / sizeof(excluded[0]); i++) {
        struct gxfp_factory_startup_options mixed = valid;
        *(bool *)((unsigned char *)&mixed + excluded[i]) = true;
        assert(!gxfp_factory_startup_valid(&mixed));
        rejected++;
    }
    const unsigned int invalid_limits[] = {0, 2, 511, 513, UINT_MAX};
    for (size_t i = 0; i < sizeof(invalid_limits) / sizeof(invalid_limits[0]); i++) {
        struct gxfp_factory_startup_options wrong = valid;
        wrong.capture_limit = invalid_limits[i];
        assert(!gxfp_factory_startup_valid(&wrong));
        rejected++;
    }
    const struct gxfp_factory_startup_options defaults = {.capture_limit = 1};
    assert(!gxfp_factory_startup_valid(&defaults));
    rejected++;
    printf("PASS: actual factory startup policy required_limit=%u rejected_vectors=%u\n",
           GXFP_FACTORY_REQUIRED_CAPTURE_LIMIT, rejected);
    return 0;
}
