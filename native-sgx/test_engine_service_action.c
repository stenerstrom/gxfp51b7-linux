/* SPDX-License-Identifier: MIT
 * Synthetic original ABI/action tests. No enclave, reader or saved template. */
#define _DEFAULT_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include "engine_service_action.h"

static unsigned char *memory;
static unsigned calls[64], sequence[128], count;
static int failure_index, inner_failure_index, preprocess_result, quality_result;
static int merge_result, finalize_result, verify_result;
static uint32_t used, progress, update_length;
static uint64_t export_length;
static EngineServiceAction state;
#define AT(p, type) (*(type *)(memory + (p)))

static int fake_call(uint64_t tcs, int index, uint64_t parameter)
{
    assert(tcs == 77 && index >= 0 && index < 64);
    calls[index]++; sequence[count++] = (unsigned)index;
    assert(count < 128);
    if (index == failure_index) return -1;
    if (index == ES_DISCARD) { assert(!parameter); return 0; }
    assert(parameter == state.scratch);
    void *wire = memory + parameter;
    if (index == inner_failure_index) { *(int32_t *)wire = 0x8008; return 0; }
    switch (index) {
    case ES_CREATE: {
        EsCreateMs *m = wire; assert(m->pad == 0 && AT(m->target, uint8_t) == 20);
        m->result = 0; break;
    }
    case ENGINE_IMAGE_PREPROCESS_ECALL: {
        EngineImagePreprocessMs *m = wire;
        assert(m->encrypted_image == 0x3000 && m->encrypted_length == 10272);
        assert(AT(m->packet_length, uint32_t) == 10272);
        assert(AT(m->image_metadata, uint32_t) == 0 && AT(m->flag, uint8_t) == 0);
        assert(AT(m->purpose, uint8_t) == (state.action == GXOE_BEGIN_ENROLL));
        m->result = preprocess_result; break;
    }
    case ES_QUALITY: *(int32_t *)wire = quality_result; break;
    case ES_MERGE: {
        EsMergeMs *m = wire;
        assert(AT(m->target, uint8_t) == 20 && AT(m->liveness, uint8_t) == 0);
        assert(AT(m->used, int32_t) == (state.metadata.used == GXOE_TARGET_COUNT ? 0 :
                                      (int32_t)state.metadata.used));
        assert(AT(m->progress, uint32_t) == state.metadata.progress);
        AT(m->hint, uint32_t) = 4; m->result = merge_result; break;
    }
    case ES_FINALIZE: {
        EsFinalizeMs *m = wire;
        AT(m->target, int32_t) = 20; AT(m->used, int32_t) = used;
        AT(m->progress, uint32_t) = progress; m->result = finalize_result; break;
    }
    case ES_QUERY: {
        EsQueryMs *m = wire;
        AT(m->target, int32_t) = 20; AT(m->used, int32_t) = used;
        AT(m->progress, uint32_t) = progress; break;
    }
    case ES_SIZE: {
        EsSizeMs *m = wire; AT(m->length, uint64_t) = export_length; m->result = 0; break;
    }
    case ES_EXPORT: {
        EsExportMs *m = wire;
        assert(m->output == state.output && m->length == export_length);
        memset(memory + m->output, 0xa5, m->length); m->result = 0; break;
    }
    case ES_VERIFY: {
        EsVerifyMs *m = wire;
        assert(m->input == state.input && m->length == state.template_length);
        assert(m->new_image == 1 && AT(m->study, uint8_t) == 1 && AT(m->liveness, uint8_t) == 0);
        for (unsigned i = 0; i < sizeof(m->pad2); i++) assert(m->pad2[i] == 0);
        AT(m->update_size, uint32_t) = update_length; m->result = verify_result; break;
    }
    case ES_UPDATE: {
        EsUpdateMs *m = wire;
        assert(m->length == update_length && m->output == state.output && !m->pad2);
        memset(memory + m->output, 0x6c, m->length); m->result = 0; break;
    }
    default: assert(!"unexpected original ECALL");
    }
    return 0;
}

static void reset(void)
{
    memset(memory, 0, 0xc00000);
    memset(calls, 0, sizeof(calls)); count = 0;
    failure_index = inner_failure_index = -1;
    preprocess_result = quality_result = merge_result = verify_result = 0;
    finalize_result = -1; used = 1; progress = 8;
    update_length = export_length = 4096;
    state = (EngineServiceAction){.memory = memory, .scratch = 0x1000,
        .input = 0x400000, .output = 0x800000, .tcs = 77, .call = fake_call};
}

int main(void)
{
    memory = calloc(1, 0xc00000); assert(memory);
    uint32_t event = 0;
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_ENROLL, 0));
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_ENROLL_ACCEPTED);
    assert(state.metadata.used == 1 && state.metadata.progress == 8 && calls[ES_CREATE] == 1);
    merge_result = -2; used = 2; progress = 16;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_RETRY);
    assert(calls[ES_FINALIZE] == 1 && calls[ES_QUERY] == 1 && state.metadata.used == 2);
    assert(state.metadata.hint == 4 && state.enrollment_live && !calls[ES_DISCARD]);
    merge_result = 0; finalize_result = 0; used = 12; progress = 100;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_ENROLL_COMPLETE);
    assert(state.done && state.metadata.blob_length == 4096 && calls[ES_SIZE] == 1 && calls[ES_EXPORT] == 1);
    assert(memory[state.output] == 0xa5 && memory[state.output + 4095] == 0xa5);
    unsigned before = count;
    assert(es_process_image(&state, 0x3000, &event) == EINVAL && count == before);
    assert(!es_action_end(&state) && calls[ES_DISCARD] == 1);
    for (unsigned i = 0; i < GXOE_TEMPLATE_MAX; i++) assert(memory[state.output + i] == 0);

    /* Every stage transport failure aborts before any next ECALL. */
    const int stages[] = {8, 9, 11, 12, 14, 15};
    for (unsigned i = 0; i < sizeof(stages)/sizeof(stages[0]); i++) {
        reset(); assert(!es_action_begin(&state, GXOE_BEGIN_ENROLL, 0));
        failure_index = stages[i]; finalize_result = 0;
        assert(es_process_image(&state, 0x3000, &event) != 0);
        assert(sequence[count - 1] == (unsigned)failure_index && !state.done);
    }
    reset(); failure_index = ES_CREATE;
    assert(es_action_begin(&state, GXOE_BEGIN_ENROLL, 0) == EIO && !state.enrollment_live);
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_ENROLL, 0));
    finalize_result = 0; export_length = GXOE_TEMPLATE_MAX + 1ULL;
    assert(es_process_image(&state, 0x3000, &event) == EOVERFLOW && !calls[ES_EXPORT]);

    /* Original poor quality is an enrollment retry but still verifies; -2
     * requests a fresh baseline without treating a poor capture as nonmatch. */
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_ENROLL, 0)); quality_result = -1;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_RETRY && !calls[ES_MERGE]);
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096)); quality_result = -1;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_MATCH);
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096)); quality_result = -2;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_RETRY && state.needs_baseline && !calls[ES_VERIFY]);

    const int decisions[] = {-2, -1, 0, 1};
    const uint32_t events[] = {GXOE_RETRY, GXOE_NO_MATCH, GXOE_MATCH, GXOE_MATCH};
    for (unsigned i = 0; i < 4; i++) {
        reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096));
        verify_result = decisions[i];
        assert(!es_process_image(&state, 0x3000, &event) && event == events[i]);
        assert(state.done == (decisions[i] != -2));
        assert(calls[ES_UPDATE] == (decisions[i] == 1));
        assert(!!(state.metadata.flags & GXOE_ADAPTIVE_UPDATE_DISCARDED) == (decisions[i] == 1));
        for (unsigned j = 0; j < 4096; j++) assert(memory[state.output + j] == 0);
    }
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096));
    verify_result = -2;
    assert(!es_process_image(&state, 0x3000, &event)); verify_result = 0;
    assert(!es_process_image(&state, 0x3000, &event) && event == GXOE_MATCH && calls[ES_VERIFY] == 2);
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096));
    verify_result = 1; update_length = GXOE_TEMPLATE_MAX + 1;
    assert(es_process_image(&state, 0x3000, &event) == EOVERFLOW && !calls[ES_UPDATE]);
    reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096));
    verify_result = 1; inner_failure_index = ES_UPDATE;
    assert(es_process_image(&state, 0x3000, &event) == EIO && !state.done);
    const int template_errors[] = {0x8001, 0x8002, 0x8006, 0x8007, 0x8008, 0x83};
    for (unsigned i = 0; i < sizeof(template_errors)/sizeof(template_errors[0]); i++) {
        reset(); assert(!es_action_begin(&state, GXOE_BEGIN_VERIFY, 4096));
        verify_result = template_errors[i]; event = 0;
        assert(es_process_image(&state, 0x3000, &event) == EIO);
        assert(!event && !state.done && !calls[ES_UPDATE]);
    }
    reset(); assert(es_action_begin(&state, GXOE_BEGIN_VERIFY, GXOE_TEMPLATE_MIN - 1) == EINVAL);
    assert(es_action_begin(&state, GXOE_BEGIN_VERIFY, GXOE_TEMPLATE_MAX + 1) == EINVAL);
    puts("Original Engine action tests passed: ABI, enrollment retention/finalization, transport aborts, original verify decisions and adaptive erasure.");
    free(memory); return 0;
}
