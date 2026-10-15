/* Synthetic control-flow checks: no device, enclave, or biometric input. */
#define ENGINE_PROBE_TEST 1
#include "engine_init_runner.c"
#include <assert.h>

static unsigned int calls;
static int mode;

static int fake_execute(int user)
{
    assert(user == 1);
    struct control *ctl = (void *)(ram + CONTROL);
    calls++;
    if (mode == 1 && calls == 1) {
        ctl->flags = 5;
        ctl->result = 0x71000;
        ctl->outside_stack = 0x72000;
        ctl->outside_frame = 0x73000;
        return 0;
    }
    if (mode == 1) {
        assert(calls == 2 && ctl->leaf == (uint64_t)-2 && ctl->rdx == 0);
        assert(ctl->outside_stack == 0x72000 && ctl->outside_frame == 0x73000);
    }
    if (mode == 2 || mode == 3 || mode == 5) {
        ctl->flags = mode == 2 ? 14 : 5; /* WBDI log ID must be rejected. */
        ctl->result = mode == 3 ? 0x80000 - 39 : 0x71000;
        return 0;
    }
    if (mode == 4) return -1;
    if (mode == 7) timed_out = 1;
    ctl->flags = UINT64_MAX;
    ctl->result = mode == 6 ? 0x1001 : 0;
    return 0;
}

static void check(int selected, int expected, unsigned int expected_calls)
{
    mode = selected;
    calls = 0;
    engine_log_ocalls = 0;
    int result = engine_call_with_executor(0x42983000, -1, PARAMS, fake_execute);
    assert(result == expected && calls == expected_calls);
    if (selected == 1) assert(engine_log_ocalls == 1);
}

static int application_case;
static int fake_application(uint64_t tcs, int index, uint64_t parameter)
{
    assert(tcs == 0x42983000 && parameter == PARAMS);
    calls++;
    if (index == ENGINE_ATTACH_ECALL) {
        assert(calls == 1);
        EngineAttachMs *ms = (void *)(ram + parameter);
        assert(ms->version_capacity == 63 && ms->configuration_size == 36);
        assert(*(uint32_t *)(ram + ms->sensor_type) == 12);
        assert(ram[ms->minimum_quality] == 25 && ram[ms->minimum_coverage] == 65);
        assert(ram[ms->overlay] == 30 && ram[ms->preoverlay] == 20);
        assert(ram[ms->liveness] == 0 && ram[ms->retry_flag] == 0);
        ms->result = application_case == 1 ? -2 : 0;
        if (application_case != 6) memcpy(ram + ms->version, "Milan_v_3.02.00.15", 18);
        return application_case == 2 ? -1 : 0;
    }
    if (index == ENGINE_OVERLAY_ECALL) {
        assert(calls == 2 && application_case != 1 && application_case != 6);
        EngineOverlayMs *ms = (void *)(ram + parameter);
        assert(ram[ms->tip_start] == 4 && ram[ms->tip_end] == 1);
        assert(ram[ms->tip_step] == 5 && ram[ms->maximum_tip_count] == 8);
        assert(ram[ms->touch_tip_switch] == 4);
        return application_case == 3 ? -1 : 0;
    }
    assert(index == ENGINE_DETACH_ECALL);
    assert(calls == ((application_case == 1 || application_case == 6) ? 2U : 3U));
    EngineDetachMs *ms = (void *)(ram + parameter);
    ms->result = application_case == 4 ? -1 : 0;
    return application_case == 5 ? -1 : 0;
}

int main(void)
{
    ram = calloc(1, RAM_SIZE);
    assert(ram);
    check(0, 0, 1);
    check(1, 0, 2);
    check(2, -1, 1);
    check(3, -1, 1);
    check(4, -1, 1);
    check(5, -1, 4096);
    check(6, -1, 1);
    timed_out = 1;
    check(0, -1, 0);
    timed_out = 0;
    check(7, -1, 1);
    timed_out = 0;
    int fd = -1;
    assert(!parse_epc_fd("3", &fd) && fd == 3);
    assert(parse_epc_fd("2", &fd) && parse_epc_fd("-1", &fd));
    assert(parse_epc_fd("3junk", &fd) && parse_epc_fd("", &fd));
    assert(parse_epc_fd("99999999999999999999999", &fd));
    assert(engine_probe_main(0, NULL) == 1);
    struct image engine = {.first_tcs = 0x42983000};
    const unsigned int expected_calls[] = {3, 2, 1, 2, 3, 3, 2};
    for (application_case = 0; application_case < 7; application_case++) {
        calls = 0;
        engine_application_calls = 0;
        int result = engine_application_probe(&engine, fake_application);
        assert(result == (application_case ? -1 : 0));
        assert(calls == expected_calls[application_case] && engine_application_calls == calls);
    }
    free(ram); ram = NULL;
    puts("{\"synthetic\":true,\"call_flow_cases\":9,\"application_cases\":7,\"fd_and_entry_checks\":true,\"hardware_used\":false}");
    return 0;
}
