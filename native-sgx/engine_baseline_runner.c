/* SPDX-License-Identifier: MIT
 * One original empty-baseline handoff. All images/calibration remain in RAM.
 * No enrollment, template access, authentication, or persistent installation.
 */
#define KVM_OUTSIDE_STACK_BOTTOM 0x180000ULL
#define KVM_OUTSIDE_STACK_TOP 0x280000ULL
#define ENGINE_PAIR_TIMEOUT_SECONDS 120
#define ENGINE_PAIR_PROBE_TEST 1
#include "engine_pair_runner.c"
#include "engine_baseline_probe.h"
#include "wbdi_image_contract.h"
#include "engine_baseline_acquisition.h"

#define BASELINE_SENSOR_ID 0x324000ULL
#define BASELINE_PACKET 0x330000ULL
static EngineCalibrationStore baseline_store;
static int baseline_sealed_fd = -1;
static int baseline_transport_failed;

static int baseline_engine_dispatch(uint64_t index, uint64_t parameter)
{
    if (index == ENGINE_CALIBRATION_READ_OCALL || index == ENGINE_CALIBRATION_WRITE_OCALL)
        return engine_calibration_store_io(&baseline_store, index, parameter, outside_pointer);
    if ((index == ENGINE_LOG_OCALL || index == ENGINE_DH_LOG_OCALL) &&
            outside_pointer(parameter, sizeof(GoodixDhLogMs))) {
        pair_log_counts[1]++;
        return 0;
    }
    fprintf(stderr, "baseline_unexpected_engine_callback=%llu\n", (unsigned long long)index);
    return -1;
}

static int baseline_wbdi_dispatch(uint64_t index, uint64_t parameter)
{
    if (index == WBDI_DH_LOG_OCALL) {
        if (!outside_pointer(parameter, sizeof(GoodixDhLogMs))) return -1;
        pair_log_counts[0]++;
        return 0;
    }
    return dispatch_ocall(index, parameter) ? -1 : 0;
}

static int baseline_call_with_executor(uint64_t tcs, int index, uint64_t parameter,
                                       int (*executor)(int))
{
    if (baseline_transport_failed) return -1;
    int result;
    if (tcs == pair_tcs[0])
        result = engine_call_with_dispatcher(tcs, index, parameter, executor,
                                             baseline_wbdi_dispatch, "wbdi");
    else if (tcs == pair_tcs[1])
        result = engine_call_with_dispatcher(tcs, index, parameter, executor,
                                             baseline_engine_dispatch, "engine");
    else result = -1;
    if (result) baseline_transport_failed = 1;
    return result;
}

static int baseline_call(uint64_t tcs, int index, uint64_t parameter)
{
    return baseline_call_with_executor(tcs, index, parameter, execute);
}

static const BaselineAcquisitionOps baseline_acquisition = {
    .ecall = baseline_call, .rpc = bridge_call, .now = monotonic_seconds
};

static int baseline_queue_state(uint64_t tcs, uint32_t expected,
                                 int (*call)(uint64_t, int, uint64_t))
{
    WbdiFrameEmptyMs *ms = (void *)(ram + PARAMS);
    ms->empty = UINT32_MAX;
    int result = call(tcs, WBDI_FRAME_EMPTY_ECALL, PARAMS);
    printf("baseline_queue_sgx_result=%d empty=%u expected=%u\n", result, ms->empty, expected);
    return result || ms->empty != expected ? -1 : 0;
}

/* Consume exactly the new decoded frame, check the original quality rule,
 * initialize the original internal baseline, and export its DH packet.
 */
static int wbdi_original_baseline(uint64_t tcs,
                                   int (*call)(uint64_t, int, uint64_t))
{
    if (baseline_queue_state(tcs, 0, call) ||
        call(tcs, WBDI_FRAME_POP_ECALL, 0) ||
        baseline_queue_state(tcs, 1, call)) return -1;
    WbdiImageBaseQualityMs *quality = (void *)(ram + PARAMS);
    *quality = (WbdiImageBaseQualityMs){.result = INT32_MIN, .rows = 64, .columns = 80};
    int result = call(tcs, WBDI_IMAGE_BASE_QUALITY_ECALL, PARAMS);
    printf("baseline_quality_sgx_result=%d application_result=%d\n", result, quality->result);
    if (result || quality->result) return -1;
    memset(ram + PARAMS, 0, PAGE);
    WbdiBaseUpdateMs *update = (void *)(ram + PARAMS);
    *update = (WbdiBaseUpdateMs){.result = INT32_MIN, .existing_base = PARAMS + 128,
                                .base_valid = PARAMS + 132, .save_base = PARAMS + 136};
    result = call(tcs, WBDI_BASE_UPDATE_ECALL, PARAMS);
    uint32_t valid = *(uint32_t *)(ram + PARAMS + 132);
    uint32_t save = *(uint32_t *)(ram + PARAMS + 136);
    printf("baseline_update_sgx_result=%d application_result=%d base_valid_output=%u save_base=%u\n",
           result, update->result, valid, save);
    /* Original cold branch sets its internal validity flag and save_base=1,
     * but does not change the caller's base_valid=0. Do not invent that output.
     */
    if (result || update->result || save != 1) return -1;
    memset(ram + BASELINE_PACKET, 0, WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE);
    WbdiEncryptedImageMs *output = (void *)(ram + PARAMS);
    *output = (WbdiEncryptedImageMs){.result = INT32_MIN, .output = BASELINE_PACKET,
                                    .capacity = WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE};
    result = call(tcs, WBDI_BASE_EXPORT_ECALL, PARAMS);
    uint32_t plaintext_length;
    memcpy(&plaintext_length, ram + BASELINE_PACKET, sizeof(plaintext_length));
    printf("baseline_export_sgx_result=%d application_result=%d plaintext_length=%u\n",
           result, output->result, plaintext_length);
    return result || output->result || plaintext_length != WBDI_IMAGE_PLAINTEXT_SIZE ? -1 : 0;
}

static int original_baseline_stage(const struct image *targets)
{
    const struct image *wbdi = &targets[0], *engine = &targets[1];
    EngineBaselineProbe application = {0};
    if (engine_calibration_store_init(&baseline_store)) return -1;
    int result = engine_baseline_probe_init(&application, engine, &baseline_store, baseline_call);
    struct stat st;
    if (fstat(baseline_sealed_fd, &st) || !S_ISREG(st.st_mode) ||
            st.st_size < 0x230 || st.st_size > 2044 ||
            fcntl(baseline_sealed_fd, F_GET_SEALS) !=
                (F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) {
        errno = EINVAL; fail("sealed encrypted BIOS RAM FD");
    }
    encrypted_bios_length = (uint32_t)st.st_size;
    read_exact(baseline_sealed_fd, ram + SEALED_INPUT, encrypted_bios_length);
    close(baseline_sealed_fd); baseline_sealed_fd = -1;
    capture_enabled = 1;
    if (!result) {
        memset(ram + PARAMS, 0, PAGE);
        *(int32_t *)(ram + PARAMS) = -1;
        *(uint32_t *)(ram + PARAMS + 4) = 7;
        result = baseline_call(wbdi->first_tcs, 0x2d, PARAMS);
        if (*(int32_t *)(ram + PARAMS)) result = -1;
    }
    int tls_initialized = 0;
    if (!result) {
        memset(ram + PARAMS, 0, PAGE);
        *(int32_t *)(ram + PARAMS) = -1;
        *(uint32_t *)(ram + PARAMS + 4) = 7;
        result = baseline_call(wbdi->first_tcs, 0x27, PARAMS);
        printf("baseline_tls_init_sgx_result=%d application_result=%d key_length_valid=%d\n",
               result, *(int32_t *)(ram + PARAMS), pmk_success_length == 48);
        if (*(int32_t *)(ram + PARAMS) || pmk_success_length != 48 || unseal_error) result = -1;
        if (!result) tls_initialized = 1;
    }
    if (!result) result = baseline_initialize_images(wbdi, &baseline_acquisition);
    if (!result) result = baseline_sensor_handshake(wbdi, &baseline_acquisition);
    if (!result) result = engine_baseline_probe_set_mode(&application);
    if (!result) {
        WbdiCommunicationModeMs *mode = (void *)(ram + PARAMS);
        mode->mode = 1;
        result = baseline_call(wbdi->first_tcs, WBDI_COMMUNICATION_MODE_ECALL, PARAMS);
    }
    if (!result) result = pair_handshake(baseline_call);
    if (!result) result = engine_baseline_probe_open(&application);
    if (!result) result = baseline_call(wbdi->first_tcs, WBDI_FRAME_CLEAR_ECALL, 0);
    if (!result) result = baseline_queue_state(wbdi->first_tcs, 1, baseline_call);
    if (!result) result = baseline_sensor_capture(wbdi, &baseline_acquisition);
    if (!result) {
        uint32_t received = 0;
        result = bridge_call(8, NULL, 0, ram + BASELINE_SENSOR_ID, ENGINE_SENSOR_ID_SIZE, &received);
        printf("baseline_sensor_identity_result=%d exact_length=%d\n", result,
               received == ENGINE_SENSOR_ID_SIZE);
        if (received != ENGINE_SENSOR_ID_SIZE) result = -1;
    }
    if (!result) result = wbdi_original_baseline(wbdi->first_tcs, baseline_call);
    if (!result) result = engine_baseline_probe_initialize(&application, BASELINE_PACKET,
                                                           WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE,
                                                           BASELINE_SENSOR_ID, 0);
    /* On any failed acquisition or callback, destroy the whole SGX context
     * instead of assuming a resumable TCS state for cleanup calls.
     */
    if (result || baseline_transport_failed) application.transport_failed = 1;
    int detached = engine_baseline_probe_close(&application);
    if (detached) result = -1;
    if (!result && tls_initialized) {
        int image_exit = baseline_call(wbdi->first_tcs, WBDI_IMAGE_EXIT_ECALL, 0);
        int tls_exit = image_exit ? -1 : baseline_call(wbdi->first_tcs, 0x28, 0);
        printf("baseline_image_exit_result=%d tls_exit_result=%d\n", image_exit, tls_exit);
        if (image_exit || tls_exit) result = -1;
    }
    uint32_t received = 0;
    int finish = bridge_call(5, NULL, 0, NULL, 0, &received);
    printf("baseline_transport_finish_result=%d\n", finish);
    if (finish) result = -1;
    close(transport_fd); transport_fd = -1;
    printf("original_baseline_probe_result=%d initialized=%d calibration_reads=%u calibration_writes=%u calibration_failed=%d\n",
           result, application.baseline_done, baseline_store.reads, baseline_store.writes, baseline_store.failed);
    engine_calibration_store_close(&baseline_store);
    explicit_bzero(ram + SEALED_INPUT, 2044);
    explicit_bzero(ram + BASELINE_SENSOR_ID, ENGINE_SENSOR_ID_SIZE);
    explicit_bzero(ram + BASELINE_PACKET, WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE);
    return result;
}

static int baseline_probe_main(int argc, char **argv)
{
    (void)pair_probe_main;
    int epc_fd;
    if (argc != 9 || parse_epc_fd(argv[1], &epc_fd) ||
            parse_epc_fd(argv[7], &baseline_sealed_fd) || parse_epc_fd(argv[8], &transport_fd) ||
            epc_fd == baseline_sealed_fd || epc_fd == transport_fd || baseline_sealed_fd == transport_fd) {
        fprintf(stderr, "Use run_engine_baseline_trial.py with three distinct inherited descriptors.\n");
        return 1;
    }
    struct stat st;
    struct sockaddr_storage address;
    socklen_t address_size = sizeof(address);
    if (fstat(transport_fd, &st) || !S_ISSOCK(st.st_mode) ||
            getsockname(transport_fd, (struct sockaddr *)&address, &address_size) ||
            address.ss_family != AF_UNIX) { errno = EINVAL; fail("private baseline transport FD"); }
    struct timeval receive_timeout = {.tv_sec = 60}, send_timeout = {.tv_sec = 5};
    if (setsockopt(transport_fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout, sizeof(receive_timeout)) ||
            setsockopt(transport_fd, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout))) fail("RPC timeout");
    return pair_probe_main_with_stage(7, argv, original_baseline_stage, "original_engine_baseline");
}

#ifndef ENGINE_BASELINE_RUNNER_TEST
int main(int argc, char **argv) { return baseline_probe_main(argc, argv); }
#endif
