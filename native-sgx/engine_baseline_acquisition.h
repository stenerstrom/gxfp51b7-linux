#ifndef ENGINE_BASELINE_ACQUISITION_H
#define ENGINE_BASELINE_ACQUISITION_H

/* Isolated copies of the bounded kvm_runner acquisition sequence. The protocol,
 * retry bounds, and completion checks are unchanged; callbacks let the original
 * Engine probe abort immediately on any rejected OCALL. Production acquisition
 * continues to use its existing helpers and dispatcher.
 * Include after the runner and wbdi_image_contract.h.
 */
typedef struct {
    int (*ecall)(uint64_t, int, uint64_t);
    int (*rpc)(uint8_t, const void *, uint32_t, void *, uint32_t, uint32_t *);
    double (*now)(void);
} BaselineAcquisitionOps;

static int baseline_initialize_images(const struct image *image,
                                      const BaselineAcquisitionOps *ops)
{
    memset(ram + PARAMS, 0, PAGE);
    WbdiImageInitMs *request = (void *)(ram + PARAMS);
    *request = (WbdiImageInitMs){.result = -1, .image_length = PARAMS + 64,
        .nav_length = PARAMS + 66, .sensor_type = PARAMS + 68, .retry_limit = 1};
    *(uint16_t *)(ram + PARAMS + 64) = WBDI_IMAGE_PLAINTEXT_SIZE;
    *(uint16_t *)(ram + PARAMS + 66) = WBDI_NAV_PLAINTEXT_SIZE;
    *(uint32_t *)(ram + PARAMS + 68) = WBDI_SENSOR_PROFILE;
    int result = ops->ecall(image->first_tcs, WBDI_IMAGE_INIT_ECALL, PARAMS);
    printf("image_init_result=%d goodix_result=0x%x\n", result, (uint32_t)request->result);
    if (result || request->result) return -1;
    memset(ram + PARAMS, 0, PAGE);
    WbdiImageSizesMs *sizes = (void *)(ram + PARAMS);
    *sizes = (WbdiImageSizesMs){.images_length = PARAMS + 64,
                               .baseline_length = PARAMS + 72};
    result = ops->ecall(image->first_tcs, WBDI_IMAGE_SIZES_ECALL, PARAMS);
    uint64_t image_size = *(uint64_t *)(ram + PARAMS + 64);
    uint64_t base_size = *(uint64_t *)(ram + PARAMS + 72);
    printf("image_size=%llu imagebase_size=%llu\n",
           (unsigned long long)image_size, (unsigned long long)base_size);
    return result || image_size != WBDI_PAIRED_ENCRYPTED_IMAGE_SIZE ||
           base_size != WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE ? -1 : 0;
}

static int baseline_sensor_handshake(const struct image *image,
                                     const BaselineAcquisitionOps *ops)
{
    uint32_t received = 0;
    int result = ops->rpc(1, NULL, 0, NULL, 0, &received);
    printf("tls_bridge_start_result=%d\n", result);
    if (result) return -1;
    double deadline = ops->now() + 25;
    for (unsigned int reads = 0; reads < 120 && ops->now() < deadline &&
            !tls_connected_count && !tls_invalid_mac_count; reads++) {
        *(int32_t *)(ram + PARAMS) = -1;
        result = ops->ecall(image->first_tcs, 0x29, PARAMS);
        int32_t retval = *(int32_t *)(ram + PARAMS);
        printf("tls_read_result=%d tls_state=%u\n", retval, tls_last_state);
        if (result || (retval < 0 && retval != -0x6900 && retval != -0x6880)) return -1;
    }
    int32_t sensor_connected = 0;
    if (tls_connected_count && !tls_invalid_mac_count)
        result = ops->rpc(4, NULL, 0, &sensor_connected, 4, &received);
    else result = -1;
    printf("tls_connected_callbacks=%u invalid_mac_callbacks=%u sensor_connected_flag=%d\n",
           tls_connected_count, tls_invalid_mac_count, sensor_connected);
    printf("tls_rx_ocalls=%llu tls_tx_ocalls=%llu bridge_crc_ok=%u bridge_crc_bad=%u\n",
           (unsigned long long)ocall_counts[0], (unsigned long long)ocall_counts[1],
           bridge_crc_ok, bridge_crc_bad);
    return result || received != 4 || sensor_connected != 1 || bridge_crc_bad ? -1 : 0;
}

static int baseline_sensor_capture(const struct image *image,
                                   const BaselineAcquisitionOps *ops)
{
    uint32_t received = 0;
    int result = ops->rpc(6, NULL, 0, NULL, 0, &received);
    printf("native_capture_request_result=%d\n", result);
    if (result) return -1;
    double deadline = ops->now() + 12;
    uint32_t authenticated_bytes = 0;
    for (unsigned int reads = 0; reads < 64 && ops->now() < deadline &&
            !tls_invalid_mac_count; reads++) {
        *(int32_t *)(ram + PARAMS) = -1;
        result = ops->ecall(image->first_tcs, 0x29, PARAMS);
        int32_t retval = *(int32_t *)(ram + PARAMS);
        printf("native_capture_read_result=%d\n", retval);
        if (result || (retval < 0 && retval != -0x6900 && retval != -0x6880)) return -1;
        if (retval > 0) { authenticated_bytes = (uint32_t)retval; break; }
    }
    /* Match the existing completion rule: authenticated TLS delivery followed
     * by independent source CRC validation, without inventing a ready callback.
     */
    printf("native_image_authenticated_plaintext_bytes=%u\n", authenticated_bytes);
    if (!authenticated_bytes || image_crc_bad || tls_invalid_mac_count) return -1;
    memset(ram + PARAMS, 0, PAGE);
    WbdiSourceExportMs *source = (void *)(ram + PARAMS);
    *source = (WbdiSourceExportMs){.output = CAPTURE_OUTPUT,
                                  .capacity = WBDI_SOURCE_PACKET_SIZE};
    memset(ram + CAPTURE_OUTPUT, 0, WBDI_SOURCE_PACKET_SIZE);
    result = ops->ecall(image->first_tcs, WBDI_SOURCE_EXPORT_ECALL, PARAMS);
    int crc_valid = chicago_packet_valid(ram + CAPTURE_OUTPUT, WBDI_SOURCE_PACKET_SIZE);
    printf("native_source_export_result=%d image_crc_valid=%d image_ready_callbacks=%u\n",
           result, crc_valid, image_ready_count);
    if (!result && crc_valid)
        result = ops->rpc(7, ram + CAPTURE_OUTPUT, WBDI_SOURCE_PACKET_SIZE, NULL, 0, &received);
    else result = -1;
    explicit_bzero(ram + CAPTURE_OUTPUT, WBDI_SOURCE_PACKET_SIZE);
    printf("native_capture_host_result=%d source_packet_erased=1 raw_image_logged=0\n", result);
    return result;
}

#endif
