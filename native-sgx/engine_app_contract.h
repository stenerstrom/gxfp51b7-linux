#ifndef ENGINE_APP_CONTRACT_H
#define ENGINE_APP_CONTRACT_H

/* Original Engine 3.02.00 initialization ABI for a bounded probe.
 * Evidence: analysis/engine-native-feasibility-2026-10-14/
 *   ecall-lifecycle-contract.json and ecall-profile12-inputs.json.
 * Pointer fields are untrusted guest virtual addresses, not host pointers.
 * These are shipped defaults plus the original sensor-12 override, not a
 * reconstruction of any existing Windows registry customization.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

enum {
    ENGINE_ATTACH_ECALL = 1,
    ENGINE_OVERLAY_ECALL = 2,
    ENGINE_DETACH_ECALL = 3,
    ENGINE_LOG_OCALL = 5,
    ENGINE_PROFILE = 12,
    ENGINE_VERSION_CAPACITY = 63,
    ENGINE_CONFIGURATION_SIZE = 36
};

typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t sensor_type;
    uint64_t minimum_quality;
    uint64_t minimum_coverage;
    uint64_t overlay;
    uint64_t preoverlay;
    uint64_t liveness;
    uint64_t retry_flag;
    uint64_t version;
    uint32_t version_capacity;
    uint32_t padding1;
    uint64_t configuration;
    uint32_t configuration_size;
    uint32_t padding2;
} EngineAttachMs;

typedef struct {
    uint64_t tip_start;
    uint64_t tip_end;
    uint64_t tip_step;
    uint64_t maximum_tip_count;
    uint64_t touch_tip_switch;
} EngineOverlayMs;

typedef struct { int32_t result; } EngineDetachMs;

typedef struct {
    uint32_t sensor_type;
    uint8_t minimum_quality, minimum_coverage, overlay, preoverlay;
    uint8_t liveness, retry_flag;
    uint8_t tip_start, tip_end, tip_step, maximum_tip_count, touch_tip_switch;
    uint8_t configuration[ENGINE_CONFIGURATION_SIZE];
    char version[64];
} EngineProbeInputs;

_Static_assert(sizeof(EngineAttachMs) == 96, "Original Attach MS size");
_Static_assert(offsetof(EngineAttachMs, result) == 0, "Attach result width/offset");
_Static_assert(offsetof(EngineAttachMs, sensor_type) == 8, "Attach sensor offset");
_Static_assert(offsetof(EngineAttachMs, minimum_quality) == 16, "Attach quality offset");
_Static_assert(offsetof(EngineAttachMs, minimum_coverage) == 24, "Attach coverage offset");
_Static_assert(offsetof(EngineAttachMs, overlay) == 32, "Attach overlay offset");
_Static_assert(offsetof(EngineAttachMs, preoverlay) == 40, "Attach preoverlay offset");
_Static_assert(offsetof(EngineAttachMs, liveness) == 48, "Attach liveness offset");
_Static_assert(offsetof(EngineAttachMs, retry_flag) == 56, "Attach retry offset");
_Static_assert(offsetof(EngineAttachMs, version) == 64, "Attach output offset");
_Static_assert(offsetof(EngineAttachMs, version_capacity) == 72, "Attach output length offset");
_Static_assert(offsetof(EngineAttachMs, configuration) == 80, "Attach config offset");
_Static_assert(offsetof(EngineAttachMs, configuration_size) == 88, "Attach config length offset");
_Static_assert(sizeof(EngineOverlayMs) == 40, "Original overlay MS size");
_Static_assert(offsetof(EngineOverlayMs, touch_tip_switch) == 32, "Overlay final input offset");
_Static_assert(sizeof(EngineDetachMs) == 4, "Original Detach MS size");

static inline void engine_probe_inputs_init(EngineProbeInputs *inputs)
{
    static const uint8_t configuration[ENGINE_CONFIGURATION_SIZE] = {
        0,0,0,0, 8,0,0,0, 5,0,0,0, 12,0,0,0, 2,0,0,0,
        4,1,3,2, 4,1,3,2, 4,1,3,2, 12,0,0,0
    };
    memset(inputs, 0, sizeof(*inputs));
    inputs->sensor_type = ENGINE_PROFILE;
    inputs->minimum_quality = 25;
    inputs->minimum_coverage = 65;
    inputs->overlay = 30;
    inputs->preoverlay = 20;
    inputs->tip_start = 4;
    inputs->tip_end = 1;
    inputs->tip_step = 5;
    inputs->maximum_tip_count = 8;
    inputs->touch_tip_switch = 4;
    memcpy(inputs->configuration, configuration, sizeof(configuration));
}

#endif
