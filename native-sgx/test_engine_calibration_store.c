/* No hardware: exercise the actual expanded OCALL window with synthetic data. */
#define KVM_OUTSIDE_STACK_BOTTOM 0x180000ULL
#define KVM_OUTSIDE_STACK_TOP 0x280000ULL
#define main unused_wbdi_trial_main
#include "kvm_runner.c"
#undef main
#include "engine_calibration_store.h"
#include <assert.h>

static const uint64_t parameter = KVM_OUTSIDE_STACK_TOP - 64;
static const uint64_t payload = KVM_OUTSIDE_STACK_TOP - 128 - ENGINE_CALIBRATION_BLOB_SIZE;

static EngineCalibrationMs *prepare(uint64_t location)
{
    EngineCalibrationMs *ms = (void *)(ram + location);
    *ms = (EngineCalibrationMs){.result = -1, .buffer = payload,
                                .length = ENGINE_CALIBRATION_BLOB_SIZE, .kind = 0};
    return ms;
}

int main(void)
{
    ram = calloc(1, RAM_SIZE);
    assert(ram);
    EngineCalibrationStore store;
    assert(engine_calibration_store_init(&store) == 0);
    EngineCalibrationMs *ms = prepare(parameter);
    memset(ram + payload, 0xa5, ENGINE_CALIBRATION_BLOB_SIZE);
    assert(engine_calibration_store_io(&store, 0, parameter, outside_pointer) == 0);
    assert(ms->result == 0 && store.reads == 1 && store.writes == 0 && !store.has_value);
    for (size_t i = 0; i < ENGINE_CALIBRATION_BLOB_SIZE; i++) assert(ram[payload + i] == 0);
    for (size_t i = 0; i < ENGINE_CALIBRATION_BLOB_SIZE; i++) ram[payload + i] = (i * 17 + 3) & 255;
    assert(engine_calibration_store_io(&store, 1, parameter, outside_pointer) == 0);
    assert(store.has_value && store.writes == 1);
    memset(ram + payload, 0, ENGINE_CALIBRATION_BLOB_SIZE);
    assert(engine_calibration_store_io(&store, 0, parameter, outside_pointer) == 0);
    for (size_t i = 0; i < ENGINE_CALIBRATION_BLOB_SIZE; i++)
        assert(ram[payload + i] == ((i * 17 + 3) & 255));
    engine_calibration_store_close(&store);
    assert(!store.data && !store.has_value && !store.reads && !store.writes);
    unsigned int failures = 0;
    for (int mode = 0; mode < 8; mode++) {
        assert(engine_calibration_store_init(&store) == 0);
        uint64_t chosen_parameter = mode == 6 ? payload + 64 : parameter;
        ms = prepare(chosen_parameter);
        if (mode == 0) ms->kind = 1;
        if (mode == 1) ms->length--;
        if (mode == 2) ms->length++;
        if (mode == 3) ms->buffer = KVM_OUTSIDE_STACK_BOTTOM - 1;
        if (mode == 4) ms->buffer = UINT64_MAX - 16;
        if (mode == 5) chosen_parameter = KVM_OUTSIDE_STACK_TOP - 31;
        assert(engine_calibration_store_io(&store, mode == 7 ? 2 : 0,
                                            chosen_parameter, outside_pointer) == -1);
        assert(store.failed && !store.reads && !store.writes && !store.has_value);
        prepare(parameter);
        assert(engine_calibration_store_io(&store, 0, parameter, outside_pointer) == -1);
        engine_calibration_store_close(&store);
        failures++;
    }
    free(ram); ram = NULL;
    printf("{\"synthetic\":true,\"calibration_bytes\":%llu,\"cold_read_write_reread\":true,\"rejected_cases\":%u,\"sticky_failure\":true,\"hardware_used\":false}\n",
           (unsigned long long)ENGINE_CALIBRATION_BLOB_SIZE, failures);
    return 0;
}
