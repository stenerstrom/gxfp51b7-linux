/* Offline ABI regression: fixed byte fixtures taken from original trusted
 * wrapper offsets, plus independent Intel SDK message-size definitions.
 * No enclave, reader, file containing biometric data, or network is opened.
 */
#include "engine_dh_contract.h"
#include "sgx_dh.h"
#include <assert.h>
#include <stdio.h>

_Static_assert(sizeof(sgx_dh_msg1_t) == GOODIX_DH_MSG1_SIZE, "SDK message 1");
_Static_assert(sizeof(sgx_dh_msg2_t) == GOODIX_DH_MSG2_SIZE, "SDK message 2");
_Static_assert(sizeof(sgx_dh_msg3_t) == GOODIX_DH_MSG3_SIZE, "SDK message 3");
_Static_assert(offsetof(sgx_dh_session_enclave_identity_t, mr_signer) == 128,
               "Original signer comparison offset matches SDK identity");

static void check_output_fixture(void)
{
    static const unsigned char expected[32] = {
        0,0,0,0x80, 0,0,0,0,
        0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
        0x40,0x02,0,0, 0,0,0,0,
        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88
    };
    GoodixDhOutputMs ms;
    memset(&ms, 0xaa, sizeof(ms));
    goodix_dh_output_init(&ms, UINT64_C(0x1122334455667788), 576,
                         UINT64_C(0x8877665544332211));
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_inout_fixture(void)
{
    static const unsigned char expected[48] = {
        0,0,0,0x80, 0,0,0,0,
        0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01,
        0x00,0x02,0,0, 0,0,0,0,
        0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
        0xc4,0x01,0,0, 0,0,0,0,
        0x28,0x27,0x26,0x25,0x24,0x23,0x22,0x21
    };
    GoodixDhInOutMs ms;
    memset(&ms, 0xaa, sizeof(ms));
    goodix_dh_inout_init(&ms, UINT64_C(0x0102030405060708), 512,
                        UINT64_C(0x1112131415161718), 452,
                        UINT64_C(0x2122232425262728));
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_input_fixture(void)
{
    static const unsigned char expected[24] = {
        0,0,0,0x80, 0,0,0,0,
        0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
        0xc4,0x01,0,0, 0,0,0,0
    };
    GoodixDhInputMs ms;
    memset(&ms, 0xaa, sizeof(ms));
    goodix_dh_input_init(&ms, UINT64_C(0x1112131415161718), 452);
    assert(memcmp(&ms, expected, sizeof(expected)) == 0);
}

static void check_fail_closed_completion(void)
{
    assert(goodix_dh_output_complete(0, 0, 576, 576, 576));
    assert(goodix_dh_output_complete(0, 0, 48, 48, 80));
    assert(!goodix_dh_output_complete(2, 0, 576, 576, 576));
    assert(!goodix_dh_output_complete(0, -0x600102, 576, 576, 576));
    assert(!goodix_dh_output_complete(0, GOODIX_DH_UNWRITTEN_RESULT, 576, 576, 576));
    assert(!goodix_dh_output_complete(0, 0, 0, 576, 576));
    assert(!goodix_dh_output_complete(0, 0, 575, 576, 576));
    assert(!goodix_dh_output_complete(0, 0, 577, 576, 1024));
    assert(!goodix_dh_output_complete(0, 0, 576, 576, 575));
    assert(!goodix_dh_output_complete(0, 0, 0, 0, 0));
}

int main(void)
{
    check_output_fixture();
    check_inout_fixture();
    check_input_fixture();
    check_fail_closed_completion();
    puts("PASS: DH ABI fixtures, SDK layouts, and fail-closed completion");
    return 0;
}
