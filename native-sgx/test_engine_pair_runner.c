/* Offline sequencing/failure checks; no SGX, reader, or biometric input. */
#define ENGINE_PAIR_PROBE_TEST 1
#include "engine_pair_runner.c"
#include <assert.h>

static unsigned int count;
static int fault_at, fault_type;
static const int expected_side[] = {0,1,0,1,1,0,0,1,0,0,1,1};
static const int expected_index[] = {62,42,63,43,44,67,66,45,68,69,46,47};
static const uint32_t expected_length[] = {576,512,452,0,80,48,80,48};

static int fake_pair_call(uint64_t tcs, int index, uint64_t parameter)
{
    assert(count < 12 && parameter == PARAMS);
    unsigned int step = count++;
    assert(tcs == pair_tcs[expected_side[step]] && index == expected_index[step]);
    if ((int)step == fault_at && fault_type == 0) return -1;
    if ((int)step == fault_at && fault_type == 1) return 0; /* Unwritten result. */
    if (step >= 8) {
        GoodixDhStatusMs *status = (void *)(ram + PARAMS);
        status->value = (step == 8 || step == 10) ? 1 : 7;
        if ((int)step == fault_at) status->value = 0;
        return 0;
    }
    uint64_t input = 0, output = 0, length_address = 0;
    uint32_t input_length = 0;
    if (step == 3) {
        GoodixDhInputMs *ms = (void *)(ram + PARAMS);
        input = ms->input; input_length = ms->input_length;
        ms->result = 0;
    } else if (step == 0 || step == 4 || step == 6) {
        GoodixDhOutputMs *ms = (void *)(ram + PARAMS);
        assert(ms->output_capacity == 1016);
        output = ms->output; length_address = ms->output_length;
        ms->result = 0;
    } else {
        GoodixDhInOutMs *ms = (void *)(ram + PARAMS);
        assert(ms->output_capacity == 1016);
        input = ms->input; input_length = ms->input_length;
        output = ms->output; length_address = ms->output_length;
        ms->result = 0;
    }
    if (input) {
        assert(input == DH_BUFFER_A || input == DH_BUFFER_B);
        assert(input_length == expected_length[step - 1]);
        assert(ram[input] == (uint8_t)step); /* Previous output survived scratch clearing. */
        assert(input != output);
    }
    if (output) {
        assert(output == DH_BUFFER_A || output == DH_BUFFER_B);
        assert(length_address == DH_LENGTH && ram[output] == 0);
        memset(ram + output, step + 1, expected_length[step]);
        *(uint32_t *)(ram + length_address) = expected_length[step];
    }
    if ((int)step == fault_at) {
        if (fault_type == 2) *(int32_t *)(ram + PARAMS) = -1;
        if (fault_type == 3 && output) *(uint32_t *)(ram + length_address) = 0;
    }
    return 0;
}

int main(void)
{
    ram = calloc(1, RAM_SIZE);
    assert(ram);
    pair_tcs[0] = 0x42900000; pair_tcs[1] = 0x44983000;
    count = 0; fault_at = -1;
    assert(pair_handshake(fake_pair_call) == 0 && count == 12);
    for (size_t i = 0; i < PAGE; i++) assert(ram[DH_BUFFER_A + i] == 0 && ram[DH_BUFFER_B + i] == 0);
    unsigned int failure_cases = 0;
    for (fault_at = 0; fault_at < 12; fault_at++) {
        for (fault_type = 0; fault_type < (fault_at < 8 ? 4 : 3); fault_type++) {
            if (fault_at == 3 && fault_type == 3) continue; /* Input-only ECALL. */
            count = 0;
            assert(pair_handshake(fake_pair_call) == -1);
            assert(count == (unsigned int)fault_at + 1); /* Never continue after failure. */
            failure_cases++;
        }
    }
    for (pair_active_side = 0; pair_active_side < 2; pair_active_side++) {
        int first = pair_active_side ? 5 : 14;
        assert(pair_dispatch(first, 0x71000) == 0);
        assert(pair_dispatch(first + 1, 0x71000) == 0);
        assert(pair_dispatch(first, 0x80000 - 39) == -1);
        assert(pair_dispatch(pair_active_side ? 14 : 5, 0x71000) == -1);
        assert(pair_dispatch(0, 0x71000) == -1);
    }
    assert(pair_probe_main(0, NULL) == 1);
    free(ram); ram = NULL;
    printf("{\"synthetic\":true,\"pair_success_case\":true,\"pair_abort_cases\":%u,\"log_dispatch_checks\":10,\"hardware_used\":false}\n", failure_cases);
    return 0;
}
