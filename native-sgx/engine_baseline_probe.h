/* SPDX-License-Identifier: MIT
 * Include after engine_init_runner.c. These isolated helpers preserve an
 * original Engine application session across one baseline initialization.
 * The coordinator owns runtime setup, paired DH, input buffers and teardown.
 * No image preprocessing, enrollment, identification or reader call occurs.
 */
#ifndef ENGINE_BASELINE_PROBE_H
#define ENGINE_BASELINE_PROBE_H
#include "engine_image_contract.h"
#include "engine_calibration_store.h"

typedef int (*EngineBaselineEcall)(uint64_t, int, uint64_t);

typedef struct {
    uint64_t tcs;
    EngineBaselineEcall call;
    EngineCalibrationStore *store;
    unsigned int calls;
    int mode_set;
    int attach_returned;
    int ready;
    int baseline_done;
    int failed;
    int transport_failed;
    int closed;
    int last_transport;
    int32_t last_application;
} EngineBaselineProbe;

/* All scratch state is confined to PARAMS..PARAMS+PAGE. The input packet
 * and sensor ID must live elsewhere in caller-owned, identity-mapped RAM.
 */
static inline int engine_baseline_input_span(uint64_t address, size_t size)
{
    if (!address || address >= RAM_SIZE || size > RAM_SIZE - address)
        return 0;
    return !(address < PARAMS + PAGE && PARAMS < address + size);
}

static inline int engine_baseline_probe_fail(EngineBaselineProbe *probe)
{
    if (probe) probe->failed = 1;
    return -1;
}

/* Initialize once for a fresh application session and an initialized RAM
 * calibration store. The coordinator must close before reusing this object.
 */
static inline int engine_baseline_probe_init(EngineBaselineProbe *probe,
                                            const struct image *engine,
                                            EngineCalibrationStore *store,
                                            EngineBaselineEcall call)
{
    if (!probe) return -1;
    memset(probe, 0, sizeof(*probe));
    probe->last_application = ENGINE_IMAGE_UNWRITTEN_RESULT;
    if (!engine || !engine->first_tcs || !store || !store->data ||
            store->failed || !call || !ram)
        return engine_baseline_probe_fail(probe);
    probe->tcs = engine->first_tcs;
    probe->call = call;
    probe->store = store;
    return 0;
}

static inline int engine_baseline_probe_call(EngineBaselineProbe *probe,
                                            int index)
{
    probe->calls++;
    probe->last_transport = probe->call(probe->tcs, index, PARAMS);
    if (probe->last_transport) {
        probe->transport_failed = 1;
        probe->ready = 0;
        return engine_baseline_probe_fail(probe);
    }
    return 0;
}

/* Original host order is mode 1, legitimate paired DH, then Attach/overlay.
 * Keep this operation separate so the coordinator can preserve that order.
 */
static inline int engine_baseline_probe_set_mode(EngineBaselineProbe *probe)
{
    if (!probe || !probe->call || probe->failed || probe->closed ||
            probe->mode_set || probe->attach_returned)
        return engine_baseline_probe_fail(probe);
    EngineCommunicationModeMs *ms = (void *)(ram + PARAMS);
    engine_communication_mode_init(ms);
    int result = engine_baseline_probe_call(probe, ENGINE_COMMUNICATION_MODE_ECALL);
    printf("engine_baseline_mode_sgx_result=%d\n", probe->last_transport);
    if (result) return -1;
    probe->mode_set = 1;
    return 0;
}

/* The coordinator must already have verified paired DH readiness. Open
 * leaves the application attached; close is mandatory after any normally
 * returned Attach, including an application error or version mismatch.
 */
static inline int engine_baseline_probe_open(EngineBaselineProbe *probe)
{
    if (!probe || !probe->call || probe->failed || probe->closed ||
            !probe->mode_set || probe->attach_returned || probe->store->failed)
        return engine_baseline_probe_fail(probe);
    const uint64_t data_address = PARAMS + 256;
    memset(ram + PARAMS, 0, PAGE);
    EngineProbeInputs *data = (void *)(ram + data_address);
    engine_probe_inputs_init(data);
    EngineAttachMs *attach = (void *)(ram + PARAMS);
#define BASELINE_INPUT_ADDRESS(member) (data_address + offsetof(EngineProbeInputs, member))
    *attach = (EngineAttachMs){
        .result = ENGINE_IMAGE_UNWRITTEN_RESULT,
        .sensor_type = BASELINE_INPUT_ADDRESS(sensor_type),
        .minimum_quality = BASELINE_INPUT_ADDRESS(minimum_quality),
        .minimum_coverage = BASELINE_INPUT_ADDRESS(minimum_coverage),
        .overlay = BASELINE_INPUT_ADDRESS(overlay),
        .preoverlay = BASELINE_INPUT_ADDRESS(preoverlay),
        .liveness = BASELINE_INPUT_ADDRESS(liveness),
        .retry_flag = BASELINE_INPUT_ADDRESS(retry_flag),
        .version = BASELINE_INPUT_ADDRESS(version),
        .version_capacity = ENGINE_VERSION_CAPACITY,
        .configuration = BASELINE_INPUT_ADDRESS(configuration),
        .configuration_size = ENGINE_CONFIGURATION_SIZE,
    };
    int result = engine_baseline_probe_call(probe, ENGINE_ATTACH_ECALL);
    probe->last_application = attach->result;
    printf("engine_baseline_attach_sgx_result=%d application_result=%d\n",
           probe->last_transport, probe->last_application);
    if (result) return -1;
    probe->attach_returned = 1;
    const char expected[] = "Milan_v_3.02.00.15";
    int version_matches = !memcmp(data->version, expected, sizeof(expected));
    printf("engine_baseline_profile=%u version_matches_original=%d\n",
           data->sensor_type, version_matches);
    if (attach->result || !version_matches || probe->store->failed)
        return engine_baseline_probe_fail(probe);
    EngineOverlayMs *overlay = (void *)(ram + PARAMS);
    *overlay = (EngineOverlayMs){
        .tip_start = BASELINE_INPUT_ADDRESS(tip_start),
        .tip_end = BASELINE_INPUT_ADDRESS(tip_end),
        .tip_step = BASELINE_INPUT_ADDRESS(tip_step),
        .maximum_tip_count = BASELINE_INPUT_ADDRESS(maximum_tip_count),
        .touch_tip_switch = BASELINE_INPUT_ADDRESS(touch_tip_switch),
    };
#undef BASELINE_INPUT_ADDRESS
    result = engine_baseline_probe_call(probe, ENGINE_OVERLAY_ECALL);
    printf("engine_baseline_overlay_sgx_result=%d\n", probe->last_transport);
    if (result) return -1;
    if (probe->store->failed) return engine_baseline_probe_fail(probe);
    probe->ready = 1;
    return 0;
}

/* Only one original baseline call is permitted. Packet and sensor ID remain
 * caller-owned; this helper neither substitutes identity nor persists input.
 * calibration_flag is the original sample's boolean update flag. Engine 7
 * validates its pointer but does not consume the value in this exact binary.
 */
static inline int engine_baseline_probe_initialize(EngineBaselineProbe *probe,
                                                  uint64_t packet,
                                                  uint32_t packet_length,
                                                  uint64_t sensor_id,
                                                  uint32_t calibration_flag)
{
    if (!probe || !probe->call || probe->failed || probe->closed ||
            !probe->ready || probe->baseline_done || probe->store->failed ||
            packet_length != ENGINE_PROFILE12_PACKET_BYTES || calibration_flag > 1 ||
            !engine_baseline_input_span(packet, packet_length) ||
            !engine_baseline_input_span(sensor_id, ENGINE_SENSOR_ID_SIZE))
        return engine_baseline_probe_fail(probe);
    uint32_t plaintext_length;
    memcpy(&plaintext_length, ram + packet, sizeof(plaintext_length));
    if (plaintext_length != ENGINE_PROFILE12_IMAGE_BYTES)
        return engine_baseline_probe_fail(probe);
    const uint64_t flag_address = PARAMS + 512;
    const uint64_t initialized_address = flag_address + 4;
    *(uint32_t *)(ram + flag_address) = calibration_flag;
    *(uint32_t *)(ram + initialized_address) = 0;
    EngineBaselineInitMs *ms = (void *)(ram + PARAMS);
    engine_baseline_init_ms(ms, packet, packet_length, sensor_id,
                            flag_address, initialized_address);
    const unsigned int previous_writes = probe->store->writes;
    int result = engine_baseline_probe_call(probe, ENGINE_BASELINE_INIT_ECALL);
    probe->last_application = ms->result;
    const uint32_t initialized = *(uint32_t *)(ram + initialized_address);
    printf("engine_baseline_init_sgx_result=%d application_result=%d initialized=%u "
           "calibration_reads=%u calibration_writes=%u calibration_failed=%d\n",
           probe->last_transport, probe->last_application, initialized,
           probe->store->reads, probe->store->writes, probe->store->failed);
    if (result) return -1;
    if (ms->result || initialized != 1 || probe->store->failed ||
            !probe->store->has_value || probe->store->writes <= previous_writes)
        return engine_baseline_probe_fail(probe);
    probe->baseline_done = 1;
    return 0;
}

/* On transport failure, perform no further ECALLs: the coordinator destroys
 * the whole enclave/VM. On ordinary application errors, Detach is still valid.
 * This function does not destroy the caller-owned RAM calibration store.
 */
static inline int engine_baseline_probe_close(EngineBaselineProbe *probe)
{
    if (!probe) return -1;
    if (probe->closed) return probe->failed ? -1 : 0;
    probe->closed = 1;
    probe->ready = 0;
    if (probe->transport_failed || !probe->attach_returned)
        return probe->failed ? -1 : 0;
    EngineDetachMs *detach = (void *)(ram + PARAMS);
    *detach = (EngineDetachMs){.result = ENGINE_IMAGE_UNWRITTEN_RESULT};
    int result = engine_baseline_probe_call(probe, ENGINE_DETACH_ECALL);
    probe->last_application = detach->result;
    printf("engine_baseline_detach_sgx_result=%d application_result=%d\n",
           probe->last_transport, probe->last_application);
    probe->attach_returned = 0;
    if (result || detach->result || probe->store->failed)
        return engine_baseline_probe_fail(probe);
    return probe->failed ? -1 : 0;
}

#endif
