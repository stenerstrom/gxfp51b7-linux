/* SPDX-License-Identifier: MIT */
#ifndef ENGINE_SERVICE_CONTRACT_H
#define ENGINE_SERVICE_CONTRACT_H
/* Exact original Engine ABI. Evidence: lifecycle-enrollment-abi.json,
 * lifecycle-enroll-host-policy.json and handoff-live-image-contract.md. */
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <string.h>
#include "engine_v2_protocol.h"

enum { ES_DISCARD = 5, ES_QUALITY = 9, ES_CREATE = 10, ES_MERGE = 11,
       ES_FINALIZE = 12, ES_SIZE = 14, ES_EXPORT = 15, ES_UPDATE = 16,
       ES_VERIFY = 17, ES_QUERY = 19, ES_DIAGNOSTICS = 20,
       ES_FILETIME_OCALL = 4, ES_WBDI_FDT = 14 };
typedef struct { int32_t result; uint32_t pad; uint64_t target; } EsCreateMs;
typedef struct {
    int32_t result; uint32_t pad;
    uint64_t target, used, progress, liveness, hint;
} EsMergeMs;
typedef struct { int32_t result; uint32_t pad; uint64_t target, used, progress; } EsFinalizeMs;
typedef struct { int32_t result; uint32_t pad; uint64_t length; } EsSizeMs;
typedef struct { int32_t result; uint32_t pad; uint64_t output, length; } EsExportMs;
typedef struct { int32_t result; uint32_t pad; uint64_t output; uint32_t length, pad2; } EsUpdateMs;
typedef struct {
    int32_t result; uint32_t pad;
    uint64_t input, length, study, update_size, liveness;
    uint8_t new_image, pad2[7];
} EsVerifyMs;
typedef struct { uint64_t progress, target, used; } EsQueryMs;
typedef struct { uint64_t quality; uint32_t length, pad; uint64_t score; } EsDiagnosticsMs;
typedef struct { uint64_t high, low; } EsFiletimeMs;
typedef struct { uint64_t sensor, threshold, tcode; } EsFdtMs;
typedef struct {
    uint16_t version, size;
    uint8_t sensor_id[16];
    uint16_t tcode;
    uint8_t threshold, flags;
} EsFactoryMetadata;
_Static_assert(sizeof(EsCreateMs) == 16, "Create ABI");
_Static_assert(sizeof(EsMergeMs) == 48, "Merge ABI");
_Static_assert(offsetof(EsMergeMs, hint) == 40, "Merge hint ABI");
_Static_assert(sizeof(EsFinalizeMs) == 32, "Finalize ABI");
_Static_assert(sizeof(EsSizeMs) == 16, "Size ABI");
_Static_assert(sizeof(EsExportMs) == 24, "Export ABI");
_Static_assert(sizeof(EsUpdateMs) == 24, "Update ABI");
_Static_assert(sizeof(EsVerifyMs) == 56, "Verify ABI");
_Static_assert(offsetof(EsVerifyMs, new_image) == 48, "Inline new-image ABI");
_Static_assert(sizeof(EsQueryMs) == 24, "Query ABI");
_Static_assert(sizeof(EsDiagnosticsMs) == 24, "Diagnostics ABI");
_Static_assert(sizeof(EsFiletimeMs) == 16, "FILETIME ABI");
_Static_assert(sizeof(EsFdtMs) == 24, "FDT ABI");
_Static_assert(sizeof(EsFactoryMetadata) == 24, "Factory metadata ABI");
_Static_assert(offsetof(EsFactoryMetadata, tcode) == 20, "Factory tcode ABI");

static inline int es_factory_valid(const EsFactoryMetadata *m)
{
    /* The values are already derived from validated factory OTP by the kernel.
     * The range follows that exact derivation, not another sensor's defaults. */
    return m->version == 1 && m->size == sizeof(*m) && m->flags == 1 &&
           m->tcode >= 80 && m->tcode <= 320 && !(m->tcode & 15);
}

static inline int es_filetime_value(const struct timespec *ts, uint64_t *value)
{
    const int64_t epoch = INT64_C(11644473600);
    if (ts->tv_nsec < 0 || ts->tv_nsec >= 1000000000L || ts->tv_sec < -epoch)
        return -1;
    uint64_t seconds = ts->tv_sec < 0 ? (uint64_t)(epoch + ts->tv_sec) :
                       (uint64_t)ts->tv_sec + (uint64_t)epoch;
    uint64_t fraction = (uint64_t)ts->tv_nsec / 100;
    if (seconds > (UINT64_MAX - fraction) / UINT64_C(10000000)) return -1;
    *value = seconds * UINT64_C(10000000) + fraction;
    return 0;
}

static inline int es_overlap(uint64_t a, size_t an, uint64_t b, size_t bn)
{
    return a <= b ? b - a < an : a - b < bn;
}

static inline int es_filetime_callback(uint64_t address,
                                       void *(*resolve)(uint64_t, size_t),
                                       int (*clock_sample)(struct timespec *))
{
    EsFiletimeMs *ms = resolve(address, sizeof(*ms));
    if (!ms) return -1;
    EsFiletimeMs copy;
    memcpy(&copy, ms, sizeof(copy));
    uint32_t *high = resolve(copy.high, 4), *low = resolve(copy.low, 4);
    if (!high || !low || es_overlap(address, sizeof(*ms), copy.high, 4) ||
        es_overlap(address, sizeof(*ms), copy.low, 4) ||
        es_overlap(copy.high, 4, copy.low, 4)) return -1;
    struct timespec ts;
    uint64_t value;
    if (clock_sample(&ts) || es_filetime_value(&ts, &value)) return -1;
    uint32_t hi = value >> 32, lo = (uint32_t)value;
    memcpy(high, &hi, 4); memcpy(low, &lo, 4);
    return 0;
}
#endif
