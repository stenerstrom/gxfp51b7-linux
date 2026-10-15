/* SPDX-License-Identifier: MIT
 * Original WBDI/Engine SGX local-attestation proof. No sensor or biometric I/O.
 */
#define ENGINE_PROBE_TEST 1
#include "engine_init_runner.c"
#include "engine_pair_launch.h"
#include "engine_dh_contract.h"

#ifndef ENGINE_PAIR_TIMEOUT_SECONDS
#define ENGINE_PAIR_TIMEOUT_SECONDS 30
#endif
#ifndef ENGINE_PAIR_TEMPLATE_IO
#define ENGINE_PAIR_TEMPLATE_IO 0
#endif

#define PAIR_ENGINE_BASE 0x44000000ULL
#define DH_BUFFER_A 0x305000ULL
#define DH_BUFFER_B 0x306000ULL
#define DH_LENGTH (PARAMS + 128)

static uint64_t pair_tcs[2]; /* WBDI, Engine */
static unsigned int pair_log_counts[2];
static int pair_active_side;

static int pair_dispatch(uint64_t index, uint64_t parameter)
{
    uint64_t first = pair_active_side == 0 ? 14 : 5;
    if ((index != first && index != first + 1) ||
            !outside_pointer(parameter, sizeof(GoodixDhLogMs))) {
        fprintf(stderr, "pair_side=%d unexpected_or_invalid_ocall=%llu\n",
                pair_active_side, (unsigned long long)index);
        return -1;
    }
    pair_log_counts[pair_active_side]++;
    return 0;
}

static int pair_call(uint64_t tcs, int call, uint64_t parameter)
{
    if (tcs == pair_tcs[0]) pair_active_side = 0;
    else if (tcs == pair_tcs[1]) pair_active_side = 1;
    else return -1;
    return engine_call_with_dispatcher(tcs, call, parameter, execute,
                                       pair_dispatch, pair_active_side ? "engine" : "wbdi");
}

static int pair_message(int side, int index, uint64_t input, uint32_t input_length,
                        uint64_t output, uint32_t expected_length,
                        int (*call)(uint64_t, int, uint64_t))
{
    const uint32_t capacity = GOODIX_DH_RELAY_PAYLOAD_CAPACITY;
    memset(ram + PARAMS, 0, PAGE);
    if (output) memset(ram + output, 0, capacity);
    if (input && output) {
        goodix_dh_inout_init((void *)(ram + PARAMS), input, input_length,
                             output, capacity, DH_LENGTH);
    } else if (output) {
        goodix_dh_output_init((void *)(ram + PARAMS), output, capacity, DH_LENGTH);
    } else {
        goodix_dh_input_init((void *)(ram + PARAMS), input, input_length);
    }
    int transport = call(pair_tcs[side], index, PARAMS);
    int32_t application = *(int32_t *)(ram + PARAMS);
    uint32_t length = *(uint32_t *)(ram + DH_LENGTH);
    printf("pair_side=%d dh_ecall=%d sgx_result=%d application_result=%d output_length=%u\n",
           side, index, transport, application, length);
    if (output)
        return goodix_dh_output_complete(transport, application, length,
                                         expected_length, capacity) ? 0 : -1;
    return transport || application ? -1 : 0;
}

static int pair_status(int side, int index, uint32_t expected,
                       int (*call)(uint64_t, int, uint64_t))
{
    memset(ram + PARAMS, 0, PAGE);
    GoodixDhStatusMs *ms = (void *)(ram + PARAMS);
    ms->value = UINT32_MAX;
    int transport = call(pair_tcs[side], index, PARAMS);
    printf("pair_side=%d state_ecall=%d sgx_result=%d value=%u expected=%u\n",
           side, index, transport, ms->value, expected);
    return transport || ms->value != expected ? -1 : 0;
}

static int pair_handshake(int (*call)(uint64_t, int, uint64_t))
{
    /* Relay only original payloads. Windows' 8-byte routing envelope belongs
     * to its host adapter; these ECALLs receive the payload after that header.
     * Reports, peer identities and cryptographic checks stay inside originals.
     */
    if (pair_message(0, WBDI_DH_SERVER_STEP1_ECALL, 0, 0,
                     DH_BUFFER_A, GOODIX_DH_MSG1_SIZE, call) ||
        pair_message(1, ENGINE_DH_CLIENT_STEP1_ECALL, DH_BUFFER_A, GOODIX_DH_MSG1_SIZE,
                     DH_BUFFER_B, GOODIX_DH_MSG2_SIZE, call) ||
        pair_message(0, WBDI_DH_SERVER_STEP2_ECALL, DH_BUFFER_B, GOODIX_DH_MSG2_SIZE,
                     DH_BUFFER_A, GOODIX_DH_MSG3_SIZE, call) ||
        pair_message(1, ENGINE_DH_CLIENT_STEP2_ECALL, DH_BUFFER_A, GOODIX_DH_MSG3_SIZE,
                     0, 0, call) ||
        pair_message(1, ENGINE_DH_GENERATE_TEST_ECALL, 0, 0,
                     DH_BUFFER_A, GOODIX_DH_TEST_PACKET_SIZE, call) ||
        pair_message(0, WBDI_DH_RETRIEVE_TEST_ECALL, DH_BUFFER_A, GOODIX_DH_TEST_PACKET_SIZE,
                     DH_BUFFER_B, GOODIX_DH_TEST_PLAINTEXT_SIZE, call) ||
        pair_message(0, WBDI_DH_GENERATE_TEST_ECALL, 0, 0,
                     DH_BUFFER_A, GOODIX_DH_TEST_PACKET_SIZE, call) ||
        pair_message(1, ENGINE_DH_RETRIEVE_TEST_ECALL, DH_BUFFER_A, GOODIX_DH_TEST_PACKET_SIZE,
                     DH_BUFFER_B, GOODIX_DH_TEST_PLAINTEXT_SIZE, call)) return -1;
    explicit_bzero(ram + DH_BUFFER_A, PAGE);
    explicit_bzero(ram + DH_BUFFER_B, PAGE);
    if (pair_status(0, WBDI_DH_IS_READY_ECALL, 1, call) ||
        pair_status(0, WBDI_DH_STATE_ECALL, GOODIX_DH_STATE_READY, call) ||
        pair_status(1, ENGINE_DH_IS_READY_ECALL, 1, call) ||
        pair_status(1, ENGINE_DH_STATE_ECALL, GOODIX_DH_STATE_READY, call)) return -1;
    return 0;
}

static int pair_probe_main_with_stage(int argc, char **argv,
                                      int (*stage)(const struct image *),
                                      const char *scope)
{
    (void)engine_probe_main; /* Share the reviewed loader without its entrypoint. */
    int epc_fd = -1;
    if (argc != 7 || parse_epc_fd(argv[1], &epc_fd) ||
            getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 ||
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fprintf(stderr, "Use run_engine_trial.py --pair with a verified build.\n");
        return 1;
    }
    setbuf(stdout, NULL);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) fail("disable core dumps");
    struct sigaction sa = {.sa_handler = timeout_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) || sigaction(SIGINT, &sa, NULL) ||
            sigaction(SIGTERM, &sa, NULL)) fail("pair signal handlers");
    alarm(ENGINE_PAIR_TIMEOUT_SECONDS);
    struct stat st;
    if (fstat(epc_fd, &st) || !S_ISCHR(st.st_mode)) { errno = EINVAL; fail("EPC FD"); }
    int kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) fail("open /dev/kvm");
    if (ioctl(kvm_fd, KVM_GET_API_VERSION, 0) != 12) { errno = ENOTSUP; fail("KVM API"); }
    int vm_fd = -1;
    void *epc = NULL;
    size_t run_size = 0;
    setup_vm(kvm_fd, epc_fd, &vm_fd, &epc, &run_size);
    printf("probe_scope=%s windows=0 reader=%d bios=%d template=%d\n", scope, !!stage, !!stage,
           ENGINE_PAIR_TEMPLATE_IO);
    struct image le = {0}, targets[2] = {{0}, {0}};
    struct engine_pair_launch_state authorization = {0};
    int result = load_image(argv[2], LE_BASE, &le);
    if (!result) {
        int fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) fail("open Intel production signature");
        if (fstat(fd, &st) || st.st_size != 1808) { errno = EINVAL; fail("signature size"); }
        read_exact(fd, ram + SIGNATURE, 1808);
        close(fd);
        memset(ram + TOKEN, 0, 1024);
        unsigned int retries = 0;
        result = initialize_enclave(le.secs, &retries);
        printf("pair_le_einit_result=%d retries=%u\n", result, retries);
    }
    if (!result) result = initialize_runtime(&le);
    for (int side = 0; !result && side < 2; side++) {
        result = load_image(argv[4 + side], side ? PAIR_ENGINE_BASE : GOODIX_BASE, &targets[side]);
        if (!result) result = engine_pair_authorize(&authorization, &le, &targets[side], argv[6], enter);
        if (!result) {
            unsigned int retries = 0;
            result = initialize_enclave(targets[side].secs, &retries);
            printf("pair_side=%d einit_result=%d retries=%u\n", side, result, retries);
        }
        explicit_bzero(ram + TOKEN, 1024);
        if (!result) {
            pair_tcs[side] = targets[side].first_tcs;
            memset(ram + PARAMS, 0, PAGE);
            *(uint64_t *)(ram + PARAMS) = conservative_cpu_features();
            *(uint64_t *)(ram + PARAMS + 16) = 1ULL << 63;
            result = pair_call(pair_tcs[side], -1, PARAMS);
            printf("pair_side=%d runtime_result=%d\n", side, result);
        }
    }
    if (!result) result = stage ? stage(targets) : pair_handshake(pair_call);
    printf("pair_probe_result=%d wbdi_logs_discarded=%u engine_logs_discarded=%u\n",
           result, pair_log_counts[0], pair_log_counts[1]);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM); sigaddset(&blocked, SIGINT); sigaddset(&blocked, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL)) fail("block cleanup signals");
    alarm(0);
    close(cpu_fd); cpu_fd = -1;
    close(vm_fd);
    struct kvm_run *finished_run = run;
    run = NULL;
    munmap(finished_run, run_size);
    munmap(epc, EPC_SIZE); close(epc_fd);
    explicit_bzero(ram, RAM_SIZE);
    munmap(ram, RAM_SIZE); ram = NULL;
    close(kvm_fd);
    printf("vm_closed=1 epc_mapping_released=1\n");
    return result ? 1 : 0;
}

static int pair_probe_main(int argc, char **argv)
{
    return pair_probe_main_with_stage(argc, argv, NULL, "original_pair_dh");
}

#ifndef ENGINE_PAIR_PROBE_TEST
int main(int argc, char **argv) { return pair_probe_main(argc, argv); }
#endif
