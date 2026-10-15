/* SPDX-License-Identifier: MIT
 * Synthetic callback, command and factory ABI checks; never opens hardware. */
#define ENGINE_SERVICE_RUNNER_TEST 1
#include "engine_service_runner.c"
#include <assert.h>

static struct timespec test_time;
static int clock_error, executed, fdt_called;
static int fake_clock(struct timespec *out) { *out = test_time; return clock_error; }
static int fake_executor(int leaf)
{
    (void)leaf; executed++;
    struct control *ctl = (void *)(ram + CONTROL);
    ctl->flags = ES_FILETIME_OCALL;
    ctl->result = 0; /* Deliberately invalid callback; do not resume. */
    return 0;
}
static int fake_fdt(uint64_t tcs, int index, uint64_t parameter)
{
    assert(tcs == 77 && index == ES_WBDI_FDT && parameter == PARAMS);
    EsFdtMs *ms = (void *)(ram + parameter);
    assert(*(uint32_t *)(ram + ms->sensor) == 12);
    assert(ram[ms->threshold] == 27 && *(uint16_t *)(ram + ms->tcode) == 128);
    fdt_called++;
    return 0;
}
int main(void)
{
    (void)engine_service_main;
    ram = calloc(1, RAM_SIZE); assert(ram);
    uint64_t where = KVM_OUTSIDE_STACK_BOTTOM + 128;
    EsFiletimeMs *ms = (void *)(ram + where);
    *ms = (EsFiletimeMs){.high = where + 16, .low = where + 20};
    uint64_t value;
    test_time = (struct timespec){.tv_sec = 0, .tv_nsec = 123456700};
    assert(!es_filetime_value(&test_time, &value) && value == UINT64_C(116444736001234567));
    assert(!es_filetime_callback(where, outside_pointer, fake_clock));
    assert(*(uint32_t *)(ram + ms->high) == value >> 32);
    assert(*(uint32_t *)(ram + ms->low) == (uint32_t)value);
    test_time = (struct timespec){.tv_sec = -INT64_C(11644473600)};
    assert(!es_filetime_value(&test_time, &value) && !value);
    test_time.tv_sec--; assert(es_filetime_value(&test_time, &value));
    test_time = (struct timespec){.tv_sec = INT64_MAX}; assert(es_filetime_value(&test_time, &value));
    test_time = (struct timespec){.tv_nsec = 1000000000}; assert(es_filetime_value(&test_time, &value));
    test_time.tv_nsec = -1; assert(es_filetime_value(&test_time, &value));
    test_time = (struct timespec){0}; clock_error = -1;
    *(uint32_t *)(ram + ms->high) = 0x1234;
    assert(es_filetime_callback(where, outside_pointer, fake_clock));
    assert(*(uint32_t *)(ram + ms->high) == 0x1234); clock_error = 0;
    ms->high = where; assert(es_filetime_callback(where, outside_pointer, fake_clock));
    ms->high = where + 16; ms->low = where + 18;
    assert(es_filetime_callback(where, outside_pointer, fake_clock));
    ms->low = KVM_OUTSIDE_STACK_TOP - 2;
    assert(es_filetime_callback(where, outside_pointer, fake_clock));
    assert(es_filetime_callback(0, outside_pointer, fake_clock));

    EsFactoryMetadata factory = {.version = 1, .size = 24, .tcode = 128,
                                 .threshold = 27, .flags = 1};
    assert(!service_fdt(77, &factory, fake_fdt) && fdt_called == 1);
    factory.flags = 0; assert(service_fdt(77, &factory, fake_fdt)); factory.flags = 1;
    factory.tcode = 127; assert(service_fdt(77, &factory, fake_fdt)); factory.tcode = 128;
    factory.version = 2; assert(service_fdt(77, &factory, fake_fdt));
    assert(fdt_called == 1);

    int wait_remove = 0;
    assert(service_classification_event(0, &wait_remove) == GXOE_WAIT_FINGER && !wait_remove);
    assert(service_classification_event(2, &wait_remove) == GXOE_WAIT_FINGER && !wait_remove);
    assert(service_classification_event(1, &wait_remove) == 0);
    wait_remove = 1;
    assert(service_classification_event(1, &wait_remove) == GXOE_WAIT_REMOVE && wait_remove);
    assert(service_classification_event(0, &wait_remove) == GXOE_WAIT_REMOVE && wait_remove);
    assert(service_classification_event(3, &wait_remove) == GXOE_WAIT_REMOVE && wait_remove);
    assert(service_classification_event(2, &wait_remove) == GXOE_WAIT_FINGER && !wait_remove);
    assert(service_classification_event(1, &wait_remove) == 0);
    assert(service_classification_event(3, &wait_remove) == GXOE_RETRY && wait_remove);
    assert(service_classification_event(1, &wait_remove) == GXOE_WAIT_REMOVE);
    assert(service_classification_event(0, &wait_remove) == GXOE_WAIT_REMOVE);
    assert(service_classification_event(2, &wait_remove) == GXOE_WAIT_FINGER && !wait_remove);

    /* An acquisition retry erases host template I/O but keeps only the paired
     * state and a real-empty gate. A STEP cannot consume an erased template. */
    service_action = (EngineServiceAction){.memory = ram, .scratch = PARAMS,
        .input = SERVICE_INPUT, .output = SERVICE_OUTPUT,
        .action = GXOE_BEGIN_VERIFY, .template_length = GXOE_TEMPLATE_MIN, .needs_baseline = 1};
    service_last_event = GXOE_RETRY; service_wait_remove = 1;
    for (int rejected = 0; rejected < 9; rejected++) {
        uint32_t operation = GXOE_END_ACTION;
        switch (rejected) {
        case 0: operation = GXOE_CLOSE_SESSION; break;
        case 1: service_action.action = GXOE_BEGIN_ENROLL; break;
        case 2: service_action.done = 1; break;
        case 3: service_action.enrollment_live = 1; break;
        case 4: service_wait_remove = 0; break;
        case 5: service_last_event = GXOE_MATCH; break;
        case 6: baseline_store.failed = 1; break;
        case 7: baseline_transport_failed = 1; break;
        case 8: timed_out = 1; break;
        }
        GxoeMetadata ack;
        assert(!service_end_retry(operation, &ack));
        service_action.action = GXOE_BEGIN_VERIFY; service_action.done = 0;
        service_action.enrollment_live = 0; service_wait_remove = 1;
        service_last_event = GXOE_RETRY; baseline_store.failed = 0;
        baseline_transport_failed = 0; timed_out = 0;
    }
    memset(ram + SERVICE_INPUT, 0x71, GXOE_TEMPLATE_MAX);
    memset(ram + SERVICE_OUTPUT, 0x42, GXOE_TEMPLATE_MAX);
    GxoeMetadata ack;
    assert(service_end_retry(GXOE_END_ACTION, &ack) == 1);
    assert(ack.flags == GXOE_RETRY_SESSION_RETAINED && !ack.blob_length && !ack.used && !ack.target);
    assert(!service_action.action && !service_action.done && !service_action.template_length);
    assert(service_action.needs_baseline && service_wait_remove && service_retry_only);
    for (unsigned i = 0; i < GXOE_TEMPLATE_MAX; i++)
        assert(!ram[SERVICE_INPUT + i] && !ram[SERVICE_OUTPUT + i]);
    uint32_t event = 0;
    assert(es_process_image(&service_action, BASELINE_PACKET, &event) == EINVAL);
    assert(!service_end_retry(GXOE_END_ACTION, &ack));
    assert(!es_action_begin(&service_action, GXOE_BEGIN_VERIFY, GXOE_TEMPLATE_MIN));
    assert(service_action.needs_baseline && service_wait_remove);

    GxoeHeader header = {.version = GXOE_VERSION, .operation = GXOE_OPEN_SESSION, .request_id = 1};
    memcpy(header.magic, GXOE_REQUEST_MAGIC, 4);
    assert(service_request_valid(&header, 0));
    header.session_id = 1; assert(!service_request_valid(&header, 0));
    service_session = 1; service_last_request = 1;
    header.operation = GXOE_BEGIN_VERIFY; header.request_id = 2; header.payload_length = GXOE_TEMPLATE_MIN;
    assert(service_request_valid(&header, 1));
    header.payload_length--; assert(!service_request_valid(&header, 1));
    header.payload_length = GXOE_TEMPLATE_MAX + 1; assert(!service_request_valid(&header, 1));
    header.operation = GXOE_STEP; header.payload_length = 0; assert(service_request_valid(&header, 1));
    header.request_id = 1; assert(!service_request_valid(&header, 1)); header.request_id = 2;
    header.session_id = 2; assert(!service_request_valid(&header, 1)); header.session_id = 1;
    header.status = 1; assert(!service_request_valid(&header, 1)); header.status = 0;
    header.operation = GXOE_OPEN_SESSION; assert(!service_request_valid(&header, 1));

    pair_tcs[0] = 77; pair_tcs[1] = 88; baseline_transport_failed = 0;
    assert(service_call_with_executor(88, ES_FINALIZE, PARAMS, fake_executor));
    assert(executed == 1 && baseline_transport_failed);
    assert(service_call_with_executor(88, ES_FINALIZE, PARAMS, fake_executor));
    assert(executed == 1); /* Sticky failure prevents resuming a rejected OCALL. */
    free(ram); ram = NULL;
    puts("Original Engine worker tests passed: real-time conversion, callback boundaries/fail-fast, factory FDT ABI and command framing.");
    return 0;
}
