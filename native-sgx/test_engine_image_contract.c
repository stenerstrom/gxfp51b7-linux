/* Offline original-ABI byte fixtures. No enclave or reader is opened. */
#include "engine_image_contract.h"
#include <assert.h>
#include <stdio.h>

static void check_mode(void)
{
    EngineCommunicationModeMs ms = { UINT32_MAX };
    static const unsigned char expected[] = { 1, 0, 0, 0 };
    engine_communication_mode_init(&ms);
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_baseline(void)
{
    static const unsigned char expected[48] = {
        0,0,0,0x80, 0,0,0,0,
        8,7,6,5,4,3,2,1,
        0x20,0x28,0,0, 0,0,0,0,
        0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
        0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,
        0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31
    };
    EngineBaselineInitMs ms;
    memset(&ms, 0xaa, sizeof(ms));
    engine_baseline_init_ms(&ms, UINT64_C(0x0102030405060708), 10272,
                            UINT64_C(0x1112131415161718),
                            UINT64_C(0x2122232425262728),
                            UINT64_C(0x3132333435363738));
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_image(void)
{
    static const unsigned char expected[56] = {
        0,0,0,0x80, 0,0,0,0,
        8,7,6,5,4,3,2,1,
        0x20,0x28,0,0, 0,0,0,0,
        0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
        0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21,
        0x38,0x37,0x36,0x35,0x34,0x33,0x32,0x31,
        0x48,0x47,0x46,0x45,0x44,0x43,0x42,0x41
    };
    EngineImagePreprocessMs ms;
    memset(&ms, 0xaa, sizeof(ms));
    engine_image_preprocess_ms(&ms, UINT64_C(0x0102030405060708), 10272,
                               UINT64_C(0x1112131415161718),
                               UINT64_C(0x2122232425262728),
                               UINT64_C(0x3132333435363738),
                               UINT64_C(0x4142434445464748));
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_callback(void)
{
    static const unsigned char original_ms[32] = {
        0,0,0,0x80, 0,0,0,0,
        8,7,6,5,4,3,2,1,
        0xc0,0x24,2,0, 0,0,0,0,
        0,0,0,0, 0,0,0,0
    };
    EngineCalibrationMs ms;
    unsigned char completed[32];
    memcpy(&ms, original_ms, sizeof(ms));
    assert(ms.result == ENGINE_IMAGE_UNWRITTEN_RESULT);
    assert(ms.buffer == UINT64_C(0x0102030405060708));
    assert(ms.length == ENGINE_CALIBRATION_BLOB_SIZE);
    assert(ms.length == 140480);
    assert(ms.kind == ENGINE_CALIBRATION_STORE_KIND);
    ms.result = 0;
    memcpy(completed, &ms, sizeof(ms));
    assert(completed[0] == 0 && completed[1] == 0 &&
           completed[2] == 0 && completed[3] == 0);
    assert(memcmp(completed + 4, original_ms + 4, 28) == 0);
    /* Length is 64-bit in the trusted callback, not a uint32 field. */
    completed[20] = 1;
    completed[24] = ENGINE_ARRANGEMENT_STORE_KIND;
    memcpy(&ms, completed, sizeof(ms));
    assert(ms.length == UINT64_C(0x1000224c0));
    assert(ms.kind == 1);
}

int main(void)
{
    check_mode();
    check_baseline();
    check_image();
    check_callback();
    puts("PASS: Engine mode, baseline, image and calibration callback ABI fixtures");
    return 0;
}
