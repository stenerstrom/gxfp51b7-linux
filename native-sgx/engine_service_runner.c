/* SPDX-License-Identifier: MIT
 * Candidate original-Engine worker. One paired session per completed operation;
 * acquisition retries across libfprint actions share it. Templates cross only the
 * private command socket. Sensor images and calibration remain transient RAM.
 */
#define ENGINE_BASELINE_RUNNER_TEST 1
#define ENGINE_PAIR_TEMPLATE_IO 1
#include "engine_baseline_runner.c"
#include "engine_service_action.h"

#define SERVICE_INPUT 0x400000ULL
#define SERVICE_OUTPUT 0x800000ULL
#define SERVICE_MAX_FRAMES 512U
#define SERVICE_ACTION_SECONDS 1200U

static int service_command_fd = -1;
static unsigned service_frames;
static uint32_t service_last_request;
static uint64_t service_session;
static GxoeHeader service_final_request;
static int service_final_pending, service_final_error;
static int service_wait_remove;
static uint32_t service_last_event;
static int service_retry_only;
static EngineServiceAction service_action;

static int service_clock(struct timespec *value) { return clock_gettime(CLOCK_REALTIME, value); }

static int service_engine_dispatch(uint64_t index, uint64_t parameter)
{
    if (index == ES_FILETIME_OCALL)
        return es_filetime_callback(parameter, outside_pointer, service_clock);
    return baseline_engine_dispatch(index, parameter);
}

static int service_call_with_executor(uint64_t tcs, int index, uint64_t parameter,
                                      int (*executor)(int))
{
    if (baseline_transport_failed) return -1;
    int result = -1;
    if (tcs == pair_tcs[0])
        result = engine_call_with_dispatcher(tcs, index, parameter, executor,
                                             baseline_wbdi_dispatch, "wbdi");
    else if (tcs == pair_tcs[1])
        result = engine_call_with_dispatcher(tcs, index, parameter, executor,
                                             service_engine_dispatch, "engine");
    if (result) baseline_transport_failed = 1;
    return result;
}
static int service_call(uint64_t tcs, int index, uint64_t parameter)
{
    return service_call_with_executor(tcs, index, parameter, execute);
}

/* The existing persistent sensor protocol needs both a fresh-frame admission
 * (RPC8) and its actual capture command (RPC6). RPC7 completes that frame. */
static int service_rpc(uint8_t op, const void *in, uint32_t length,
                        void *out, uint32_t capacity, uint32_t *received)
{
    if (op == 6) {
        if (service_frames >= SERVICE_MAX_FRAMES) return -1;
        if (service_frames) {
            uint32_t n = 0;
            int admitted = 0;
            if (bridge_call(8, NULL, 0, &admitted, sizeof(admitted), &n) ||
                n != sizeof(admitted) || admitted != 1) return -1;
        }
        service_frames++;
        image_crc_ok = 0; image_ready_count = 0;
        /* Bad CRC/MAC counts remain sticky and cannot be erased by a retry. */
    }
    return bridge_call(op, in, length, out, capacity, received);
}
static const BaselineAcquisitionOps service_acquisition = {
    .ecall = service_call, .rpc = service_rpc, .now = monotonic_seconds
};

static int service_socket_read(void *buffer, size_t length)
{
    unsigned char *p = buffer;
    while (length && !timed_out) {
        ssize_t n = recv(service_command_fd, p, length, 0);
        if (n > 0) { p += n; length -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR && !timed_out) continue;
        return -1;
    }
    return length ? -1 : 0;
}
static int service_socket_write(const void *buffer, size_t length)
{
    const unsigned char *p = buffer;
    while (length && !timed_out) {
        ssize_t n = send(service_command_fd, p, length, MSG_NOSIGNAL);
        if (n > 0) { p += n; length -= (size_t)n; continue; }
        if (n < 0 && errno == EINTR && !timed_out) continue;
        return -1;
    }
    return length ? -1 : 0;
}
static int service_reply(const GxoeHeader *request, int error, uint32_t event,
                          const GxoeMetadata *metadata, const void *blob)
{
    GxoeHeader reply = *request;
    memcpy(reply.magic, GXOE_RESPONSE_MAGIC, 4);
    reply.version = GXOE_VERSION; reply.session_id = service_session;
    reply.status = error; reply.event = error ? 0 : event;
    reply.payload_length = error ? 0 : sizeof(*metadata) + metadata->blob_length;
    if (service_socket_write(&reply, sizeof(reply))) return -1;
    if (!error && (service_socket_write(metadata, sizeof(*metadata)) ||
        (metadata->blob_length && service_socket_write(blob, metadata->blob_length)))) return -1;
    return 0;
}

static int service_request_valid(const GxoeHeader *h, int opened)
{
    if (memcmp(h->magic, GXOE_REQUEST_MAGIC, 4) || h->version != GXOE_VERSION ||
        h->status || h->event || !h->request_id || h->request_id <= service_last_request)
        return 0;
    if ((!opened && (h->operation != GXOE_OPEN_SESSION || h->session_id)) ||
        (opened && h->session_id != service_session)) return 0;
    if (h->operation == GXOE_BEGIN_VERIFY)
        return h->payload_length >= GXOE_TEMPLATE_MIN && h->payload_length <= GXOE_TEMPLATE_MAX;
    return h->payload_length == 0 && h->operation >= GXOE_OPEN_SESSION &&
           h->operation <= GXOE_CLOSE_SESSION && (!opened || h->operation != GXOE_OPEN_SESSION);
}

static int service_fdt(uint64_t tcs, const EsFactoryMetadata *metadata,
                        int (*call)(uint64_t, int, uint64_t))
{
    if (!es_factory_valid(metadata)) return -1;
    memset(ram + PARAMS, 0, PAGE);
    EsFdtMs *ms = (void *)(ram + PARAMS);
    *ms = (EsFdtMs){.sensor = PARAMS + 128, .threshold = PARAMS + 132, .tcode = PARAMS + 134};
    *(uint32_t *)(ram + PARAMS + 128) = WBDI_SENSOR_PROFILE;
    ram[PARAMS + 132] = metadata->threshold;
    *(uint16_t *)(ram + PARAMS + 134) = metadata->tcode;
    return call(tcs, ES_WBDI_FDT, PARAMS);
}

static int service_current_image(const struct image *wbdi, int *classification)
{
    if (baseline_queue_state(wbdi->first_tcs, 1, service_call) ||
        baseline_sensor_capture(wbdi, &service_acquisition)) return -1;
    if (baseline_queue_state(wbdi->first_tcs, 0, service_call) ||
        service_call(wbdi->first_tcs, WBDI_FRAME_POP_ECALL, 0) ||
        baseline_queue_state(wbdi->first_tcs, 1, service_call)) return -1;
    memset(ram + PARAMS, 0, PAGE);
    memset(ram + BASELINE_PACKET, 0, WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE);
    WbdiEncryptedImageMs *ms = (void *)(ram + PARAMS);
    *ms = (WbdiEncryptedImageMs){.result = INT32_MIN, .output = BASELINE_PACKET,
                                .capacity = WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE};
    if (service_call(wbdi->first_tcs, WBDI_FIRST_IMAGE_ECALL, PARAMS)) return -1;
    *classification = ms->result;
    printf("service_original_classifier=%d\n", *classification);
    uint32_t plaintext;
    memcpy(&plaintext, ram + BASELINE_PACKET, 4);
    if (*classification < 0 || *classification > 3 || plaintext != WBDI_IMAGE_PLAINTEXT_SIZE)
        return -1;
    return 0;
}

static int service_refresh_baseline(const struct image *wbdi, EngineBaselineProbe *application)
{
    if (baseline_queue_state(wbdi->first_tcs, 1, service_call) ||
        baseline_sensor_capture(wbdi, &service_acquisition) ||
        wbdi_original_baseline(wbdi->first_tcs, service_call)) return -1;
    /* Reuse the checked original calibration handshake with fresh baseline.
     * This does not destroy the enrollment session or its accepted images. */
    application->baseline_done = 0;
    return engine_baseline_probe_initialize(application, BASELINE_PACKET,
        WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE, BASELINE_SENSOR_ID, 0);
}

/* Zero means a new down image may enter Engine8. Every nonzero event consumes
 * no enrollment/verification image. A temperature frame is not a finger lift. */
static uint32_t service_classification_event(int classification, int *wait_remove)
{
    if (classification == 2) { *wait_remove = 0; return GXOE_WAIT_FINGER; }
    if (*wait_remove) return GXOE_WAIT_REMOVE;
    if (classification == 0) return GXOE_WAIT_FINGER;
    if (classification == 1) return 0;
    *wait_remove = 1;
    return GXOE_RETRY;
}

/* fprintd ends a libfprint verify action on an acquisition retry, then starts
 * another action in the same claim. Preserve only this healthy, nonfinal path.
 * The original per-image preparation replaces the current image on retry;
 * completed identity decisions still destroy their worker. */
static int service_end_retry(uint32_t operation, GxoeMetadata *acknowledgement)
{
    if (operation != GXOE_END_ACTION || service_action.action != GXOE_BEGIN_VERIFY ||
        service_action.done || service_action.enrollment_live || !service_wait_remove ||
        service_last_event != GXOE_RETRY || baseline_store.failed ||
        baseline_transport_failed || timed_out) return 0;
    if (es_action_end(&service_action)) return -1;
    *acknowledgement = (GxoeMetadata){.flags = GXOE_RETRY_SESSION_RETAINED};
    service_last_event = GXOE_READY;
    service_retry_only = 1;
    printf("service_retry_worker_retained=1 frames=%u\n", service_frames);
    return 1;
}

static int service_step(const struct image *wbdi, EngineBaselineProbe *application, uint32_t *event)
{
    if (!service_action.action || service_action.done) return EINVAL;
    int classification = -1;
    if (service_current_image(wbdi, &classification)) return EIO;
    int result = 0;
    *event = service_classification_event(classification, &service_wait_remove);
    if (classification == 2) {
        if (service_action.needs_baseline) {
            if (service_refresh_baseline(wbdi, application)) result = EIO;
            else service_action.needs_baseline = 0;
        }
        *event = GXOE_WAIT_FINGER;
    } else if (*event == GXOE_RETRY) {
        service_action.metadata.hint = 10;
    } else if (!*event) {
        result = es_process_image(&service_action, BASELINE_PACKET, event);
        service_wait_remove = 1;
    }
    explicit_bzero(ram + BASELINE_PACKET, WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE);
    return result;
}

static int service_start(const struct image *targets, EngineBaselineProbe *application,
                          int *tls_initialized, int *images_initialized)
{
    const struct image *wbdi = &targets[0], *engine = &targets[1];
    if (engine_calibration_store_init(&baseline_store) ||
        engine_baseline_probe_init(application, engine, &baseline_store, service_call)) return EIO;
    struct stat st;
    if (fstat(baseline_sealed_fd, &st) || !S_ISREG(st.st_mode) ||
        st.st_size < 0x230 || st.st_size > 2044 ||
        fcntl(baseline_sealed_fd, F_GET_SEALS) !=
            (F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) return EINVAL;
    encrypted_bios_length = (uint32_t)st.st_size;
    read_exact(baseline_sealed_fd, ram + SEALED_INPUT, encrypted_bios_length);
    close(baseline_sealed_fd); baseline_sealed_fd = -1;
    capture_enabled = 1;
    memset(ram + PARAMS, 0, PAGE);
    *(int32_t *)(ram + PARAMS) = INT32_MIN;
    *(uint32_t *)(ram + PARAMS + 4) = 7;
    if (service_call(wbdi->first_tcs, 45, PARAMS) || *(int32_t *)(ram + PARAMS)) return EIO;
    *(int32_t *)(ram + PARAMS) = INT32_MIN;
    if (service_call(wbdi->first_tcs, 39, PARAMS) || *(int32_t *)(ram + PARAMS) ||
        pmk_success_length != 48 || unseal_error) return EIO;
    *tls_initialized = 1;
    if (baseline_initialize_images(wbdi, &service_acquisition)) return EIO;
    *images_initialized = 1;
    if (baseline_sensor_handshake(wbdi, &service_acquisition) ||
        engine_baseline_probe_set_mode(application)) return EIO;
    *(uint32_t *)(ram + PARAMS) = 1;
    if (service_call(wbdi->first_tcs, WBDI_COMMUNICATION_MODE_ECALL, PARAMS) ||
        pair_handshake(service_call) || engine_baseline_probe_open(application)) return EIO;
    EsFactoryMetadata metadata = {0};
    uint32_t received = 0;
    int error = bridge_call(9, NULL, 0, &metadata, sizeof(metadata), &received);
    if (error || received != sizeof(metadata) || !es_factory_valid(&metadata)) {
        explicit_bzero(&metadata, sizeof(metadata)); return EPROTO;
    }
    memcpy(ram + BASELINE_SENSOR_ID, metadata.sensor_id, ENGINE_SENSOR_ID_SIZE);
    error = service_fdt(wbdi->first_tcs, &metadata, service_call);
    explicit_bzero(&metadata, sizeof(metadata));
    if (error || service_call(wbdi->first_tcs, WBDI_FRAME_CLEAR_ECALL, 0) ||
        baseline_queue_state(wbdi->first_tcs, 1, service_call) ||
        service_refresh_baseline(wbdi, application)) return EIO;
    service_action = (EngineServiceAction){.memory = ram, .scratch = PARAMS,
        .input = SERVICE_INPUT, .output = SERVICE_OUTPUT, .tcs = engine->first_tcs,
        .call = service_call};
    return 0;
}

static int service_stage(const struct image *targets)
{
    EngineBaselineProbe application = {0};
    int tls_initialized = 0, images_initialized = 0, result = 0, opened = 0;
    GxoeHeader request;
    if (service_socket_read(&request, sizeof(request))) { result = EPIPE; goto cleanup; }
    if (!service_request_valid(&request, 0)) { result = EPROTO; goto pending; }
    service_last_request = request.request_id;
    result = service_start(targets, &application, &tls_initialized, &images_initialized);
    if (result) goto pending;
    service_session = 1; opened = 1;
    GxoeMetadata ready = {.target = GXOE_TARGET_COUNT, .flags = GXOE_REQUIRES_EMPTY_START};
    if (service_reply(&request, 0, GXOE_READY, &ready, NULL)) { result = EPIPE; goto cleanup; }
    alarm(SERVICE_ACTION_SECONDS);
    while (!timed_out) {
        if (service_socket_read(&request, sizeof(request))) { result = EPIPE; break; }
        if (!service_request_valid(&request, opened)) { result = EPROTO; goto pending; }
        service_last_request = request.request_id;
        uint32_t event = GXOE_READY;
        if (request.operation == GXOE_END_ACTION) {
            GxoeMetadata acknowledgement;
            int retained = service_end_retry(request.operation, &acknowledgement);
            if (retained < 0) { result = EIO; goto pending; }
            if (retained) {
                if (service_reply(&request, 0, GXOE_CLOSED, &acknowledgement, NULL)) {
                    result = EPIPE; break;
                }
                continue;
            }
        }
        if (request.operation == GXOE_CLOSE_SESSION || request.operation == GXOE_END_ACTION)
            goto pending;
        if (service_retry_only && request.operation != GXOE_BEGIN_VERIFY) {
            result = EINVAL; goto pending;
        }
        if (request.operation == GXOE_BEGIN_VERIFY) {
            if (service_action.action || service_socket_read(ram + SERVICE_INPUT, request.payload_length)) {
                result = service_action.action ? EBUSY : EPIPE; goto pending;
            }
            result = es_action_begin(&service_action, GXOE_BEGIN_VERIFY, request.payload_length);
        } else if (request.operation == GXOE_BEGIN_ENROLL) {
            result = es_action_begin(&service_action, GXOE_BEGIN_ENROLL, 0);
        } else if (request.operation == GXOE_STEP) {
            result = service_step(&targets[0], &application, &event);
        } else result = EINVAL;
        if (result || baseline_store.failed || baseline_transport_failed) {
            if (!result) result = EIO;
            goto pending;
        }
        service_retry_only = 0;
        service_last_event = event;
        if (service_reply(&request, 0, event, &service_action.metadata,
                           ram + SERVICE_OUTPUT)) { result = EPIPE; break; }
        if (event == GXOE_ENROLL_COMPLETE) {
            explicit_bzero(ram + SERVICE_OUTPUT, service_action.metadata.blob_length);
            service_action.metadata.blob_length = 0;
        }
    }
    if (timed_out) result = ETIMEDOUT;
    goto cleanup;
pending:
    service_final_request = request;
    service_final_pending = 1;
cleanup:
    /* A rejected OCALL must never be resumed. On such failures the enclosing
     * paired loader destroys all enclaves instead of issuing cleanup ECALLs. */
    if (!baseline_transport_failed && !timed_out) {
        if (service_action.memory && es_action_end(&service_action)) result = EIO;
        if (baseline_transport_failed) application.transport_failed = 1;
        if (engine_baseline_probe_close(&application)) result = EIO;
        if (!baseline_transport_failed && images_initialized &&
            service_call(targets[0].first_tcs, WBDI_IMAGE_EXIT_ECALL, 0)) result = EIO;
        if (!baseline_transport_failed && tls_initialized &&
            service_call(targets[0].first_tcs, 40, 0)) result = EIO;
    }
    uint32_t received = 0;
    if (bridge_call(5, NULL, 0, NULL, 0, &received)) result = EIO;
    close(transport_fd); transport_fd = -1;
    if (baseline_sealed_fd >= 0) { close(baseline_sealed_fd); baseline_sealed_fd = -1; }
    engine_calibration_store_close(&baseline_store);
    explicit_bzero(ram + SEALED_INPUT, 2044);
    explicit_bzero(ram + BASELINE_SENSOR_ID, ENGINE_SENSOR_ID_SIZE);
    explicit_bzero(ram + BASELINE_PACKET, WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE);
    explicit_bzero(ram + SERVICE_INPUT, GXOE_TEMPLATE_MAX);
    explicit_bzero(ram + SERVICE_OUTPUT, GXOE_TEMPLATE_MAX);
    service_final_error = result;
    printf("original_engine_service_result=%d frames=%u discarded_adaptive_update=%u\n",
           result, service_frames, !!(service_action.metadata.flags & GXOE_ADAPTIVE_UPDATE_DISCARDED));
    return result ? -1 : 0;
}

static int service_validate_socket(int fd, unsigned receive_seconds)
{
    struct stat st;
    struct sockaddr_storage address;
    socklen_t length = sizeof(address);
    int type = 0; socklen_t type_length = sizeof(type);
    if (fstat(fd, &st) || !S_ISSOCK(st.st_mode) ||
        getsockname(fd, (struct sockaddr *)&address, &length) || address.ss_family != AF_UNIX ||
        getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &type_length) || type != SOCK_STREAM) return -1;
    struct timeval receive = {.tv_sec = receive_seconds}, send = {.tv_sec = 5};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &receive, sizeof(receive)) ||
           setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &send, sizeof(send)) ? -1 : 0;
}

static int engine_service_main(int argc, char **argv)
{
    (void)baseline_probe_main;
    int epc;
    if (argc != 10 || parse_epc_fd(argv[1], &epc) ||
        parse_epc_fd(argv[7], &baseline_sealed_fd) || parse_epc_fd(argv[8], &transport_fd) ||
        parse_epc_fd(argv[9], &service_command_fd)) return 1;
    int descriptors[] = {epc, baseline_sealed_fd, transport_fd, service_command_fd};
    for (unsigned i = 0; i < 4; i++) for (unsigned j = i + 1; j < 4; j++)
        if (descriptors[i] == descriptors[j]) return 1;
    if (service_validate_socket(transport_fd, 60) ||
        service_validate_socket(service_command_fd, SERVICE_ACTION_SECONDS)) return 1;
    int result = pair_probe_main_with_stage(7, argv, service_stage, "original_engine_service");
    /* Pair teardown has destroyed EPC mappings and wiped guest memory before
     * this final acknowledgment. The parent also validates sensor restoration. */
    if (service_final_pending) {
        GxoeMetadata closed = {0};
        int error = service_final_error ? service_final_error : result ? EIO : 0;
        if (service_reply(&service_final_request, error, GXOE_CLOSED, &closed, NULL)) result = 1;
    }
    close(service_command_fd); service_command_fd = -1;
    return result ? 1 : 0;
}
#ifndef ENGINE_SERVICE_RUNNER_TEST
int main(int argc, char **argv) { return engine_service_main(argc, argv); }
#endif
