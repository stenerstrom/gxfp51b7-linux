#ifndef ENGINE_IMAGE_CONTRACT_H
#define ENGINE_IMAGE_CONTRACT_H

/* Exact original Engine 3.02.00 marshaling for calibration and preparation.
 * Evidence: analysis/engine-native-feasibility-2026-10-14/
 * lifecycle-calibration-contract.json and trusted wrappers 90b0, 6df0, 70c0,
 * b2e0 and b610. This header does not access a reader or execute an enclave.
 * All pointer fields contain mapped untrusted guest addresses, not host pointers.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The original Engine ABI requires little-endian marshaling"
#endif

#define ENGINE_CALIBRATION_BLOB_SIZE UINT64_C(0x224c0)
#define ENGINE_CALIBRATION_PAYLOAD_SIZE UINT64_C(0x224b0)
#define ENGINE_IMAGE_UNWRITTEN_RESULT INT32_MIN

enum {
    ENGINE_COMMUNICATION_MODE_ECALL = 33,
    ENGINE_BASELINE_INIT_ECALL = 7,
    ENGINE_IMAGE_PREPROCESS_ECALL = 8,
    ENGINE_CALIBRATION_READ_OCALL = 0,
    ENGINE_CALIBRATION_WRITE_OCALL = 1,
    ENGINE_CALIBRATION_STORE_KIND = 0,
    ENGINE_ARRANGEMENT_STORE_KIND = 1,
    ENGINE_DIRECT_DH_MODE = 1,
    ENGINE_SENSOR_ID_SIZE = 16,
    ENGINE_PROFILE12_WIDTH = 80,
    ENGINE_PROFILE12_HEIGHT = 64,
    ENGINE_PROFILE12_IMAGE_BYTES = 10240,
    ENGINE_PROFILE12_PACKET_BYTES = 10272,
    ENGINE_IMAGE_PURPOSE_IDENTIFY = 0,
    ENGINE_IMAGE_PURPOSE_ENROLL = 1
};

/* Input only; no inner result field. Check the ECALL transport status. */
typedef struct {
    uint32_t mode;
} EngineCommunicationModeMs;

typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t encrypted_baseline;
    uint32_t encrypted_length;
    uint32_t padding1;
    uint64_t sensor_id;
    uint64_t calibration_flag;
    uint64_t initialized;
} EngineBaselineInitMs;

/* All pointed-to fields are input only. Only result is copied back.
 * packet_length points to uint32 and controls the actual decrypt length;
 * encrypted_length controls the trusted wrapper's accessible input span.
 * The coordinator must validate both against the actual source packet.
 */
typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t encrypted_image;
    uint32_t encrypted_length;
    uint32_t padding1;
    uint64_t image_metadata;
    uint64_t flag;
    uint64_t packet_length;
    uint64_t purpose;
} EngineImagePreprocessMs;

/* Original callbacks return 0, even for missing files or short transfers.
 * A diagnostic host must separately record callback errors: the original
 * baseline path ignores the callbacks' returned status. Kind 0 is the
 * sensor-prefixed calibration blob; kind 1 is a separate arrangement store.
 */
typedef struct {
    int32_t result;
    uint32_t padding;
    uint64_t buffer;
    uint64_t length;
    uint8_t kind;
    uint8_t padding2[7];
} EngineCalibrationMs;

_Static_assert(sizeof(EngineCommunicationModeMs) == 4, "Communication mode MS");
_Static_assert(sizeof(EngineBaselineInitMs) == 48, "Baseline init MS");
_Static_assert(offsetof(EngineBaselineInitMs, encrypted_baseline) == 8, "Baseline pointer");
_Static_assert(offsetof(EngineBaselineInitMs, encrypted_length) == 16, "Baseline length");
_Static_assert(offsetof(EngineBaselineInitMs, sensor_id) == 24, "Sensor ID pointer");
_Static_assert(offsetof(EngineBaselineInitMs, calibration_flag) == 32, "Calibration flag pointer");
_Static_assert(offsetof(EngineBaselineInitMs, initialized) == 40, "Initialized flag pointer");
_Static_assert(sizeof(EngineImagePreprocessMs) == 56, "Image preprocess MS");
_Static_assert(offsetof(EngineImagePreprocessMs, encrypted_image) == 8, "Image pointer");
_Static_assert(offsetof(EngineImagePreprocessMs, encrypted_length) == 16, "Image length");
_Static_assert(offsetof(EngineImagePreprocessMs, image_metadata) == 24, "Image metadata pointer");
_Static_assert(offsetof(EngineImagePreprocessMs, flag) == 32, "Image flag pointer");
_Static_assert(offsetof(EngineImagePreprocessMs, packet_length) == 40, "Packet length pointer");
_Static_assert(offsetof(EngineImagePreprocessMs, purpose) == 48, "Image purpose pointer");
_Static_assert(sizeof(EngineCalibrationMs) == 32, "Calibration callback MS");
_Static_assert(offsetof(EngineCalibrationMs, buffer) == 8, "Calibration buffer pointer");
_Static_assert(offsetof(EngineCalibrationMs, length) == 16, "Calibration uint64 length");
_Static_assert(offsetof(EngineCalibrationMs, kind) == 24, "Calibration kind byte");
_Static_assert(ENGINE_CALIBRATION_PAYLOAD_SIZE + ENGINE_SENSOR_ID_SIZE ==
               ENGINE_CALIBRATION_BLOB_SIZE, "Sensor-prefixed calibration size");

static inline void engine_communication_mode_init(EngineCommunicationModeMs *ms)
{
    ms->mode = ENGINE_DIRECT_DH_MODE;
}

/* The caller must supply valid non-NULL guest pointers to all fields.
 * sensor_id points to 16 bytes; calibration_flag and initialized point to
 * uint32 values. Only initialized is copied back by the trusted wrapper.
 */
static inline void engine_baseline_init_ms(EngineBaselineInitMs *ms,
                                          uint64_t encrypted_baseline,
                                          uint32_t encrypted_length,
                                          uint64_t sensor_id,
                                          uint64_t calibration_flag,
                                          uint64_t initialized)
{
    memset(ms, 0, sizeof(*ms));
    ms->result = ENGINE_IMAGE_UNWRITTEN_RESULT;
    ms->encrypted_baseline = encrypted_baseline;
    ms->encrypted_length = encrypted_length;
    ms->sensor_id = sensor_id;
    ms->calibration_flag = calibration_flag;
    ms->initialized = initialized;
}

/* image_metadata and packet_length point to uint32; flag and purpose point
 * to uint8. A declaration of this ABI does not establish their host policy.
 */
static inline void engine_image_preprocess_ms(EngineImagePreprocessMs *ms,
                                             uint64_t encrypted_image,
                                             uint32_t encrypted_length,
                                             uint64_t image_metadata,
                                             uint64_t flag,
                                             uint64_t packet_length,
                                             uint64_t purpose)
{
    memset(ms, 0, sizeof(*ms));
    ms->result = ENGINE_IMAGE_UNWRITTEN_RESULT;
    ms->encrypted_image = encrypted_image;
    ms->encrypted_length = encrypted_length;
    ms->image_metadata = image_metadata;
    ms->flag = flag;
    ms->packet_length = packet_length;
    ms->purpose = purpose;
}

#endif
