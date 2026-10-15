/* SPDX-License-Identifier: MIT
 * Isolated startup probe for the unchanged original Goodix Engine enclave.
 * Reuses the existing SGX/KVM loader, never its WBDI application calls.
 * No reader transport, BIOS input, biometric input, or stored template is used.
 */
#define main unused_wbdi_trial_main
#include "kvm_runner.c"
#undef main
#include "engine_app_contract.h"

static unsigned int engine_log_ocalls;
static unsigned int engine_application_calls;

/* Engine helper 0x1010 -> wrapper 0xaf70 -> OCALL 5. The 40-byte
 * marshalling record contains level, file, function, line and message;
 * there is no return-value member. Discard all original diagnostic strings.
 */
static int engine_dispatch(uint64_t index, uint64_t parameter)
{
    if (index != 5 || !outside_pointer(parameter, 40)) {
        fprintf(stderr, "engine_unsupported_or_invalid_ocall=%llu\n",
                (unsigned long long)index);
        return -1;
    }
    engine_log_ocalls++;
    return 0;
}

static int engine_call_with_dispatcher(uint64_t tcs, int call, uint64_t parameter,
                                      int (*executor)(int),
                                      int (*dispatch)(uint64_t, uint64_t),
                                      const char *label)
{
    struct control *ctl = (void *)(ram + CONTROL);
    *ctl = (struct control){.leaf = (uint64_t)(int64_t)call, .rbx = tcs, .rdx = parameter};
    for (unsigned int count = 0; count < 4096 && !timed_out; count++) {
        if (executor(1) || timed_out) return -1;
        if (ctl->flags == UINT64_MAX) {
            printf("%s_ecall_number=%d sgx_result=0x%llx ocalls=%u\n", label, call,
                   (unsigned long long)ctl->result, count);
            return ctl->result ? -1 : 0;
        }
        if (dispatch(ctl->flags, ctl->result)) return -1;
        uint64_t stack = ctl->outside_stack, frame = ctl->outside_frame;
        *ctl = (struct control){.leaf = (uint64_t)(int64_t)-2, .rbx = tcs,
                                .outside_stack = stack, .outside_frame = frame};
    }
    fprintf(stderr, "engine_call_cancelled_or_ocall_limit=1\n");
    return -1;
}

static int engine_call_with_executor(uint64_t tcs, int call, uint64_t parameter,
                                     int (*executor)(int))
{
    return engine_call_with_dispatcher(tcs, call, parameter, executor,
                                       engine_dispatch, "engine");
}

static int initialize_engine_runtime(const struct image *engine)
{
    memset(ram + PARAMS, 0, PAGE);
    *(uint64_t *)(ram + PARAMS) = conservative_cpu_features();
    *(uint64_t *)(ram + PARAMS + 16) = 1ULL << 63;
    return engine_call_with_executor(engine->first_tcs, -1, PARAMS, execute);
}

static int engine_call(uint64_t tcs, int call, uint64_t parameter)
{
    return engine_call_with_executor(tcs, call, parameter, execute);
}

/* Only the original application lifecycle is exercised. The shipped profile
 * is not a claim about Windows registry overrides on this computer.
 */
static int engine_application_probe(const struct image *engine,
                                    int (*call)(uint64_t, int, uint64_t))
{
    const uint64_t data_address = PARAMS + 256;
    memset(ram + PARAMS, 0, PAGE);
    EngineProbeInputs *data = (void *)(ram + data_address);
    engine_probe_inputs_init(data);
    EngineAttachMs *attach = (void *)(ram + PARAMS);
#define INPUT_ADDRESS(member) (data_address + offsetof(EngineProbeInputs, member))
    *attach = (EngineAttachMs){
        .result = -1,
        .sensor_type = INPUT_ADDRESS(sensor_type),
        .minimum_quality = INPUT_ADDRESS(minimum_quality),
        .minimum_coverage = INPUT_ADDRESS(minimum_coverage),
        .overlay = INPUT_ADDRESS(overlay),
        .preoverlay = INPUT_ADDRESS(preoverlay),
        .liveness = INPUT_ADDRESS(liveness),
        .retry_flag = INPUT_ADDRESS(retry_flag),
        .version = INPUT_ADDRESS(version),
        .version_capacity = ENGINE_VERSION_CAPACITY,
        .configuration = INPUT_ADDRESS(configuration),
        .configuration_size = ENGINE_CONFIGURATION_SIZE,
    };
    engine_application_calls++;
    int transport = call(engine->first_tcs, ENGINE_ATTACH_ECALL, PARAMS);
    printf("engine_attach_sgx_result=%d application_result=%d\n", transport, attach->result);
    if (transport) return -1;
    int result = attach->result ? -1 : 0;
    const char expected[] = "Milan_v_3.02.00.15";
    int version_matches = !memcmp(data->version, expected, sizeof(expected));
    printf("engine_profile=%u version_matches_original=%d\n", data->sensor_type, version_matches);
    if (!version_matches) result = -1;
    if (!result) {
        EngineOverlayMs *overlay = (void *)(ram + PARAMS);
        *overlay = (EngineOverlayMs){
            .tip_start = INPUT_ADDRESS(tip_start),
            .tip_end = INPUT_ADDRESS(tip_end),
            .tip_step = INPUT_ADDRESS(tip_step),
            .maximum_tip_count = INPUT_ADDRESS(maximum_tip_count),
            .touch_tip_switch = INPUT_ADDRESS(touch_tip_switch),
        };
        engine_application_calls++;
        transport = call(engine->first_tcs, ENGINE_OVERLAY_ECALL, PARAMS);
        printf("engine_overlay_sgx_result=%d\n", transport);
        if (transport) return -1;
    }
#undef INPUT_ADDRESS
    /* A normally returned Attach, including an application error, permits
     * Detach. A failed SGX transport instead falls through to VM destruction.
     */
    EngineDetachMs *detach = (void *)(ram + PARAMS);
    *detach = (EngineDetachMs){.result = -1};
    engine_application_calls++;
    transport = call(engine->first_tcs, ENGINE_DETACH_ECALL, PARAMS);
    printf("engine_detach_sgx_result=%d application_result=%d\n", transport, detach->result);
    return result || transport || detach->result ? -1 : 0;
}

static int parse_epc_fd(const char *text, int *value)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno || end == text || *end || parsed < 3 || parsed > 0x7fffffff)
        return -1;
    *value = (int)parsed;
    return 0;
}

static int engine_probe_main(int argc, char **argv)
{
    int epc_fd = -1;
    int application_mode = argc == 7 && !strcmp(argv[6], "application");
    if ((argc != 6 && !application_mode) || parse_epc_fd(argv[1], &epc_fd) ||
            getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 ||
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fprintf(stderr, "Use run_engine_trial.py with a verified build and inherited EPC FD.\n");
        return 1;
    }
    setbuf(stdout, NULL);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) fail("disable core dumps");
    struct sigaction sa = {.sa_handler = timeout_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL) || sigaction(SIGINT, &sa, NULL) ||
            sigaction(SIGTERM, &sa, NULL)) fail("probe signal handlers");
    alarm(30);
    struct stat st;
    if (fstat(epc_fd, &st) || !S_ISCHR(st.st_mode)) {
        errno = EINVAL; fail("inherited EPC FD");
    }
    int kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) fail("open /dev/kvm");
    if (ioctl(kvm_fd, KVM_GET_API_VERSION, 0) != 12) {
        errno = ENOTSUP; fail("KVM API");
    }
    int vm_fd = -1;
    void *epc = NULL;
    size_t run_size = 0;
    setup_vm(kvm_fd, epc_fd, &vm_fd, &epc, &run_size);
    printf("probe_scope=%s windows=0 reader=0 bios=0 template=0\n",
           application_mode ? "engine_application_lifecycle" : "engine_runtime_init");
    struct image le = {0}, engine = {0};
    int result = load_image(argv[2], LE_BASE, &le);
    if (!result) {
        int fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) fail("open Intel production signature");
        if (fstat(fd, &st) || st.st_size != 1808) {
            errno = EINVAL; fail("production signature size");
        }
        read_exact(fd, ram + SIGNATURE, 1808);
        close(fd);
        memset(ram + TOKEN, 0, 1024);
        unsigned int retries = 0;
        result = initialize_enclave(le.secs, &retries);
        printf("intel_le_einit_result=%d retries=%u\n", result, retries);
    }
    if (!result) {
        result = initialize_runtime(&le);
        printf("intel_le_runtime_result=%d\n", result);
    }
    if (!result) result = load_image(argv[4], GOODIX_BASE, &engine);
    if (!result) result = authorize_goodix(&le, &engine, argv[5]);
    int engine_einit_attempted = 0, engine_runtime_attempted = 0;
    if (!result) {
        unsigned int retries = 0;
        engine_einit_attempted = 1;
        result = initialize_enclave(engine.secs, &retries);
        printf("engine_einit_result=%d retries=%u\n", result, retries);
        explicit_bzero(ram + TOKEN, 1024);
    }
    if (!result) {
        engine_runtime_attempted = 1;
        result = initialize_engine_runtime(&engine);
        printf("engine_runtime_init_result=%d\n", result);
    }
    if (!result && application_mode) result = engine_application_probe(&engine, engine_call);
    printf("engine_probe_result=%d einit_attempted=%d runtime_attempted=%d application_calls=%u\n",
           result, engine_einit_attempted, engine_runtime_attempted, engine_application_calls);
    printf("engine_log_callbacks_discarded=%u\n", engine_log_ocalls);
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGALRM);
    sigaddset(&blocked, SIGINT);
    sigaddset(&blocked, SIGTERM);
    if (sigprocmask(SIG_BLOCK, &blocked, NULL)) fail("block cleanup signals");
    alarm(0);
    close(cpu_fd); cpu_fd = -1;
    close(vm_fd);
    struct kvm_run *finished_run = run;
    run = NULL;
    munmap(finished_run, run_size);
    munmap(epc, EPC_SIZE);
    close(epc_fd);
    explicit_bzero(ram, RAM_SIZE);
    munmap(ram, RAM_SIZE); ram = NULL;
    close(kvm_fd);
    printf("vm_closed=1 epc_mapping_released=1\n");
    return result ? 1 : 0;
}

#ifndef ENGINE_PROBE_TEST
int main(int argc, char **argv)
{
    return engine_probe_main(argc, argv);
}
#endif
