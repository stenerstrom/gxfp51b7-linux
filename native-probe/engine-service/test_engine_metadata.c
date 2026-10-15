/* Exercise the actual retained factory-to-wire metadata helper, no hardware. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint8_t u8;
#define memzero_explicit(p, n) memset((p), 0, (n))
#include "../engine_identity.h"
#include "../chicago_factory_config.h"
#include "../engine_metadata.h"

int main(void)
{
    struct gxfp_engine_identity identity = {.valid = true};
    struct chicago_factory_calibration factory = {.tcode = 0x140, .threshold = 28, .timing_valid = 1};
    u8 result[GXFP_ENGINE_METADATA_SIZE];
    for (unsigned i = 0; i < sizeof(identity.bytes); ++i) identity.bytes[i] = i + 1;
    assert(gxfp_engine_metadata_encode(result, &identity, &factory, true, true));
    assert(result[0] == 1 && result[1] == 0 && result[2] == 24 && result[3] == 0);
    assert(!memcmp(result + 4, identity.bytes, 16));
    assert(result[20] == 0x40 && result[21] == 1 && result[22] == 28 && result[23] == 1);
    for (unsigned which = 0; which < 5; ++which) {
        struct gxfp_engine_identity invalid_identity = identity;
        struct chicago_factory_calibration invalid_factory = factory;
        if (which == 0) invalid_identity.valid = false;
        if (which == 1) invalid_factory.timing_valid = 0;
        if (which == 2) invalid_factory.tcode = 0;
        memset(result, 0xff, sizeof(result));
        assert(!gxfp_engine_metadata_encode(result, &invalid_identity, &invalid_factory,
                                           which != 3, which != 4));
        for (unsigned i = 0; i < sizeof(result); ++i) assert(result[i] == 0);
    }
    puts("PASS: exact factory metadata and invalid-state erasure");
}
