#ifndef WBDI_IMAGE_CONTRACT_H
#define WBDI_IMAGE_CONTRACT_H

/* Original WBDI image and baseline ABI. No reader or enclave execution here.
 * Evidence: analysis/engine-native-feasibility-2026-10-14/handoff-wbdi-*.c
 * Addresses are untrusted guest virtual addresses. Original x86-64 ABI.
 */
#include <stddef.h>
#include <stdint.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The original image ABI requires little-endian marshaling"
#endif

enum {
    WBDI_IMAGE_EXIT_ECALL = 1,
    WBDI_IMAGE_INIT_ECALL = 2,
    WBDI_FRAME_CLEAR_ECALL = 3,
    WBDI_FRAME_EMPTY_ECALL = 4,
    WBDI_FRAME_POP_ECALL = 5,
    WBDI_IMAGE_BASE_QUALITY_ECALL = 7,
    WBDI_NAV_FROM_IMAGE_ECALL = 15,
    WBDI_SOURCE_EXPORT_ECALL = 21,
    WBDI_BASE_UPDATE_ECALL = 26,
    WBDI_BASE_CHECK_ECALL = 27,
    WBDI_COMMUNICATION_MODE_ECALL = 28,
    WBDI_IMAGE_SIZES_ECALL = 35,
    WBDI_FIRST_IMAGE_ECALL = 36,
    WBDI_BASE_EXPORT_ECALL = 38,
    WBDI_SELECTED_IMAGE_ECALL = 42,
    WBDI_SENSOR_PROFILE = 12,
    WBDI_IMAGE_ROWS = 64,
    WBDI_IMAGE_COLUMNS = 80,
    WBDI_IMAGE_PLAINTEXT_SIZE = 10240,
    WBDI_NAV_PLAINTEXT_SIZE = 3200,
    WBDI_SOURCE_PACKET_SIZE = 10564,
    WBDI_SINGLE_ENCRYPTED_IMAGE_SIZE = 10272,
    WBDI_PAIRED_ENCRYPTED_IMAGE_SIZE = 20544,
    WBDI_SENSOR_INFO_SIZE = 84,
    WBDI_SENSOR_INFO_ID_OFFSET = 1,
    WBDI_SENSOR_ID_SIZE = 16,
    WBDI_SENSOR_INFO_CHIP_ID_OFFSET = 72,
    WBDI_SENSOR_INFO_TYPE_OFFSET = 76
};

/* ECALL2: pointed-to lengths are uint16; sensor_type is uint32.
 * one_key_retry=0 and retry_limit=1 are the existing bounded acquisition inputs.
 */
typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t image_length;
    uint64_t nav_length;
    uint64_t sensor_type;
    uint32_t one_key_retry;
    uint32_t retry_limit;
} WbdiImageInitMs;

/* ECALL28 has no vendor result. mode=1 selects original direct DH. */
typedef struct { uint32_t mode; } WbdiCommunicationModeMs;

/* ECALL4 returns 1 for empty, 0 for available. ECALL3, ECALL5 and ECALL15 require a
 * NULL marshal pointer, not a pointer to an empty struct. Pop does not itself
 * report an empty queue; check ECALL4 before consuming a frame.
 */
typedef struct { uint32_t empty; } WbdiFrameEmptyMs;

/* ECALL7: original gf_check_image_base passes profile height before width.
 * It checks the current frame using the original preprocessor, then releases
 * that temporary preprocessing state. Require both SGX and vendor success.
 */
typedef struct {
    int32_t result;
    uint32_t rows;
    uint32_t columns;
} WbdiImageBaseQualityMs;

/* ECALL26: existing_base is uint32 input only; base_valid and save_base are
 * uint32 in/out values. For a fresh session existing_base=0 invokes original
 * baseline initialization from the current frame. It clears the current frame
 * and sets save_base=1; this output is a persistence request, not file I/O.
 * The cold branch leaves base_valid unchanged, so zero is a valid output when
 * the three input flags start at zero. Encrypted export38 checks the enclave's
 * own internal baseline-valid flag, which the cold branch does set to one.
 */
typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t existing_base;
    uint64_t base_valid;
    uint64_t save_base;
} WbdiBaseUpdateMs;

/* ECALL27: imagebase_need_update is uint32 output, base_valid is uint32 in/out.
 * Its vendor result can be 0 or 1 as a normal state decision; it is not a
 * substitute for ECALL26 when constructing the first baseline.
 */
typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t imagebase_need_update;
    uint64_t base_valid;
} WbdiBaseCheckMs;

/* ECALL35: two uint64 output pointers, no vendor-result slot. */
typedef struct { uint64_t images_length, baseline_length; } WbdiImageSizesMs;

/* ECALL36/38: uint64 capacity, no output-length pointer. Successful envelope
 * length comes from ECALL35 plus its uint32 plaintext-length header. ECALL36
 * returns the touch classifier result after encryption and clears the frame;
 * ECALL38 returns zero on successful baseline export.
 */
typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t output;
    uint64_t capacity;
} WbdiEncryptedImageMs;

typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t output;
    uint64_t capacity;
    uint32_t one_key_retry;
    uint32_t index;
} WbdiSelectedImageMs;

/* ECALL21: raw source packet export, uint16 capacity, no vendor result.
 * This packet is useful for independent CRC/completion checks. It is not an
 * encrypted Engine baseline and must not be passed to Engine7 as such.
 */
typedef struct {
    uint64_t output;
    uint16_t capacity;
    uint8_t padding[6];
} WbdiSourceExportMs;

_Static_assert(sizeof(WbdiImageInitMs) == 40, "WBDI image-init MS");
_Static_assert(offsetof(WbdiImageInitMs, image_length) == 8, "Image length pointer");
_Static_assert(offsetof(WbdiImageInitMs, nav_length) == 16, "Navigation length pointer");
_Static_assert(offsetof(WbdiImageInitMs, sensor_type) == 24, "Sensor type pointer");
_Static_assert(offsetof(WbdiImageInitMs, one_key_retry) == 32, "Retry flag");
_Static_assert(offsetof(WbdiImageInitMs, retry_limit) == 36, "Retry limit");
_Static_assert(sizeof(WbdiCommunicationModeMs) == 4, "Communication mode input");
_Static_assert(sizeof(WbdiFrameEmptyMs) == 4, "Frame-empty output");
_Static_assert(sizeof(WbdiImageBaseQualityMs) == 12, "Image-base quality MS");
_Static_assert(offsetof(WbdiImageBaseQualityMs, rows) == 4, "Quality rows input");
_Static_assert(offsetof(WbdiImageBaseQualityMs, columns) == 8, "Quality columns input");
_Static_assert(sizeof(WbdiBaseUpdateMs) == 32, "Base-update MS");
_Static_assert(offsetof(WbdiBaseUpdateMs, existing_base) == 8, "Existing-base input");
_Static_assert(offsetof(WbdiBaseUpdateMs, base_valid) == 16, "Base validity");
_Static_assert(offsetof(WbdiBaseUpdateMs, save_base) == 24, "Base persistence request");
_Static_assert(sizeof(WbdiBaseCheckMs) == 24, "Base-check MS");
_Static_assert(offsetof(WbdiBaseCheckMs, imagebase_need_update) == 8, "Base update flag");
_Static_assert(offsetof(WbdiBaseCheckMs, base_valid) == 16, "Base validity");
_Static_assert(sizeof(WbdiImageSizesMs) == 16, "Size-query MS");
_Static_assert(sizeof(WbdiEncryptedImageMs) == 24, "Encrypted image MS");
_Static_assert(offsetof(WbdiEncryptedImageMs, output) == 8, "Encrypted output pointer");
_Static_assert(offsetof(WbdiEncryptedImageMs, capacity) == 16, "Encrypted capacity width");
_Static_assert(sizeof(WbdiSelectedImageMs) == 32, "Selected image MS");
_Static_assert(offsetof(WbdiSelectedImageMs, one_key_retry) == 24, "Selected retry flag");
_Static_assert(offsetof(WbdiSelectedImageMs, index) == 28, "Selected image index");
_Static_assert(sizeof(WbdiSourceExportMs) == 16, "Source export MS");
_Static_assert(offsetof(WbdiSourceExportMs, capacity) == 8, "Source capacity width");

#endif
