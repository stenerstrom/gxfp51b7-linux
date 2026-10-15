/* SPDX-License-Identifier: MIT */
#ifndef ENGINE_SERVICE_ACTION_H
#define ENGINE_SERVICE_ACTION_H
#include <errno.h>
#include <stdio.h>
#include "engine_service_contract.h"
#include "engine_image_contract.h"

/* A command action owns one live original enrollment or verification state.
 * All guest spans below are preallocated by the coordinator. No storage I/O. */
typedef struct {
    unsigned char *memory;
    uint64_t scratch, input, output, tcs;
    int (*call)(uint64_t, int, uint64_t);
    GxoeMetadata metadata;
    uint32_t template_length;
    int action, done, enrollment_live, needs_baseline;
} EngineServiceAction;

static inline void es_scratch(EngineServiceAction *s)
{
    memset(s->memory + s->scratch, 0, 1024);
}
static inline int es_invoke(EngineServiceAction *s, int index)
{
    int transport = s->call(s->tcs, index, s->scratch);
    printf("service_action_stage=%d service_sgx_status=%d\n", index, transport);
    if (!transport && index != ES_QUERY)
        printf("service_action_stage=%d service_application_result=%d\n", index,
               *(int32_t *)(s->memory + s->scratch));
    return transport ? EIO : 0;
}
static inline int es_application(EngineServiceAction *s)
{
    return *(int32_t *)(s->memory + s->scratch);
}
static inline int es_action_begin(EngineServiceAction *s, int action, uint32_t length)
{
    if (s->action || s->done || s->enrollment_live) return EBUSY;
    if (action != GXOE_BEGIN_ENROLL && action != GXOE_BEGIN_VERIFY) return EINVAL;
    if (action == GXOE_BEGIN_VERIFY &&
        (length < GXOE_TEMPLATE_MIN || length > GXOE_TEMPLATE_MAX)) return EINVAL;
    memset(&s->metadata, 0, sizeof(s->metadata));
    s->metadata.target = GXOE_TARGET_COUNT;
    if (action == GXOE_BEGIN_ENROLL) {
        es_scratch(s);
        EsCreateMs *ms = (void *)(s->memory + s->scratch);
        *ms = (EsCreateMs){.result = INT32_MIN, .target = s->scratch + 128};
        s->memory[s->scratch + 128] = GXOE_TARGET_COUNT;
        if (es_invoke(s, ES_CREATE) || ms->result) return EIO;
        s->enrollment_live = 1;
    }
    s->template_length = length;
    s->action = action;
    return 0;
}

static inline int es_read_progress(EngineServiceAction *s, int finalize, int *complete)
{
    es_scratch(s);
    uint64_t target = s->scratch + 128, used = target + 4, progress = used + 4;
    int result = -1;
    if (finalize) {
        EsFinalizeMs *ms = (void *)(s->memory + s->scratch);
        *ms = (EsFinalizeMs){.result = INT32_MIN, .target = target,
                             .used = used, .progress = progress};
        if (es_invoke(s, ES_FINALIZE)) return EIO;
        result = ms->result;
        if (result != 0 && result != -1) return EIO;
    } else {
        EsQueryMs *ms = (void *)(s->memory + s->scratch);
        *ms = (EsQueryMs){.progress = progress, .target = target, .used = used};
        if (es_invoke(s, ES_QUERY)) return EIO;
    }
    int32_t t = *(int32_t *)(s->memory + target), u = *(int32_t *)(s->memory + used);
    uint32_t p = *(uint32_t *)(s->memory + progress);
    if (t != GXOE_TARGET_COUNT || u < 0 || u > 512) return EPROTO;
    s->metadata.target = (uint32_t)t; s->metadata.used = (uint32_t)u;
    s->metadata.progress = p;
    *complete = result == 0;
    return 0;
}

static inline int es_export_enrollment(EngineServiceAction *s)
{
    es_scratch(s);
    EsSizeMs *size = (void *)(s->memory + s->scratch);
    *size = (EsSizeMs){.result = INT32_MIN, .length = s->scratch + 128};
    if (es_invoke(s, ES_SIZE) || size->result) return EIO;
    uint64_t length = *(uint64_t *)(s->memory + s->scratch + 128);
    if (length < GXOE_TEMPLATE_MIN || length > GXOE_TEMPLATE_MAX) return EOVERFLOW;
    es_scratch(s);
    EsExportMs *out = (void *)(s->memory + s->scratch);
    *out = (EsExportMs){.result = INT32_MIN, .output = s->output, .length = length};
    memset(s->memory + s->output, 0, (size_t)length);
    if (es_invoke(s, ES_EXPORT) || out->result) {
        explicit_bzero(s->memory + s->output, (size_t)length);
        return EIO;
    }
    s->metadata.blob_length = (uint32_t)length;
    s->done = 1;
    return 0;
}

static inline int es_merge_image(EngineServiceAction *s, uint32_t *event)
{
    es_scratch(s);
    uint64_t b = s->scratch + 128;
    EsMergeMs *ms = (void *)(s->memory + s->scratch);
    *ms = (EsMergeMs){.result = INT32_MIN, .target = b, .used = b + 4,
        .progress = b + 8, .liveness = b + 12, .hint = b + 16};
    s->memory[b] = GXOE_TARGET_COUNT;
    /* Mirror the original host's input reset at the target. The existing
     * enclave session still owns its real count; this is only recovery input. */
    *(int32_t *)(s->memory + b + 4) = s->metadata.used == GXOE_TARGET_COUNT ? 0 :
                                    (int32_t)s->metadata.used;
    *(uint32_t *)(s->memory + b + 8) = s->metadata.progress;
    /* Shipped profile12 liveness is zero; Attach has the same value. */
    if (es_invoke(s, ES_MERGE)) return EIO;
    int result = ms->result;
    s->metadata.hint = *(uint32_t *)(s->memory + b + 16);
    if (result == -1) { s->metadata.hint = 10; *event = GXOE_RETRY; return 0; }
    if (result != 0 && result != -2) return EIO;
    int complete = 0;
    int error = es_read_progress(s, result == 0, &complete);
    if (error) return error;
    /* -2 has already added an image. Preserve the enrollment; do not finalize
     * here because the original host only finalizes after an ordinary add. */
    if (result == -2) { *event = GXOE_RETRY; return 0; }
    if (!complete) { *event = GXOE_ENROLL_ACCEPTED; return 0; }
    error = es_export_enrollment(s);
    if (!error) *event = GXOE_ENROLL_COMPLETE;
    return error;
}

static inline int es_verify_image(EngineServiceAction *s, uint32_t *event)
{
    es_scratch(s);
    uint64_t b = s->scratch + 128;
    EsVerifyMs *ms = (void *)(s->memory + s->scratch);
    *ms = (EsVerifyMs){.result = INT32_MIN, .input = s->input,
        .length = s->template_length, .study = b, .update_size = b + 4,
        .liveness = b + 8, .new_image = 1};
    /* Original EngineAdapter Attach 0x180016288 sets context+0x9c=1.
     * We retain its study request but intentionally discard adaptive output. */
    s->memory[b] = 1;
    if (es_invoke(s, ES_VERIFY)) return EIO;
    int result = ms->result;
    uint32_t update = *(uint32_t *)(s->memory + b + 4);
    if (result == -2) { s->metadata.hint = 7; *event = GXOE_RETRY; return 0; }
    if (result == -1) { *event = GXOE_NO_MATCH; s->done = 1; return 0; }
    if (result != 0 && result != 1) return EIO;
    if (result == 1) {
        if (update < GXOE_TEMPLATE_MIN || update > GXOE_TEMPLATE_MAX) return EOVERFLOW;
        es_scratch(s);
        EsUpdateMs *out = (void *)(s->memory + s->scratch);
        *out = (EsUpdateMs){.result = INT32_MIN, .output = s->output, .length = update};
        memset(s->memory + s->output, 0, update);
        int error = es_invoke(s, ES_UPDATE);
        int inner = out->result;
        explicit_bzero(s->memory + s->output, update);
        if (error || inner) return EIO;
        s->metadata.flags |= GXOE_ADAPTIVE_UPDATE_DISCARDED;
    }
    *event = GXOE_MATCH; s->done = 1;
    return 0;
}

static inline int es_process_image(EngineServiceAction *s, uint64_t packet, uint32_t *event)
{
    if (!s->action || s->done) return EINVAL;
    s->metadata.hint = 0;
    es_scratch(s);
    uint64_t b = s->scratch + 128;
    EngineImagePreprocessMs *ms = (void *)(s->memory + s->scratch);
    engine_image_preprocess_ms(ms, packet, ENGINE_PROFILE12_PACKET_BYTES,
                               b, b + 4, b + 8, b + 12);
    *(uint32_t *)(s->memory + b + 8) = ENGINE_PROFILE12_PACKET_BYTES;
    s->memory[b + 12] = s->action == GXOE_BEGIN_ENROLL;
    if (es_invoke(s, ENGINE_IMAGE_PREPROCESS_ECALL)) return EIO;
    /* The original host maps any returned preprocessing rejection to a bad
     * capture; SGX transport and callback failures are separately fatal. */
    if (ms->result) { s->metadata.hint = 10; *event = GXOE_RETRY; return 0; }
    es_scratch(s);
    *(int32_t *)(s->memory + s->scratch) = INT32_MIN;
    if (es_invoke(s, ES_QUALITY)) return EIO;
    int quality = es_application(s);
    if (quality != 0 && quality != -1 && quality != -2) return EIO;
    if (quality == -2) {
        s->needs_baseline = 1; s->metadata.hint = 7; *event = GXOE_RETRY; return 0;
    }
    if (quality == -1 && s->action == GXOE_BEGIN_ENROLL) {
        s->metadata.hint = 7; *event = GXOE_RETRY; return 0;
    }
    return s->action == GXOE_BEGIN_ENROLL ? es_merge_image(s, event) : es_verify_image(s, event);
}

static inline int es_action_end(EngineServiceAction *s)
{
    int result = 0;
    if (s->enrollment_live) result = s->call(s->tcs, ES_DISCARD, 0) ? EIO : 0;
    explicit_bzero(s->memory + s->input, GXOE_TEMPLATE_MAX);
    explicit_bzero(s->memory + s->output, GXOE_TEMPLATE_MAX);
    s->enrollment_live = 0; s->template_length = 0; s->action = 0;
    return result;
}
#endif
