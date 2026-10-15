#ifndef ENGINE_DH_CONTRACT_H
#define ENGINE_DH_CONTRACT_H

/* Exact Goodix Engine 3.02.00 / WBDI local-attestation marshaling.
 * Evidence: analysis/engine-native-feasibility-2026-10-14/handoff-contract.md.
 * This file does not execute enclaves or implement cryptography. All address
 * fields are untrusted guest virtual addresses, never host process pointers.
 * Native structs below require the original x86-64 little-endian ABI.
 */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The original DH ABI requires little-endian marshaling"
#endif

enum {
    ENGINE_DH_CLIENT_STEP1_ECALL = 42,
    ENGINE_DH_CLIENT_STEP2_ECALL = 43,
    ENGINE_DH_GENERATE_TEST_ECALL = 44,
    ENGINE_DH_RETRIEVE_TEST_ECALL = 45,
    ENGINE_DH_IS_READY_ECALL = 46,
    ENGINE_DH_STATE_ECALL = 47,
    ENGINE_DH_LOG_OCALL = 6,
    WBDI_DH_SERVER_STEP1_ECALL = 62,
    WBDI_DH_SERVER_STEP2_ECALL = 63,
    WBDI_DH_GENERATE_TEST_ECALL = 66,
    WBDI_DH_RETRIEVE_TEST_ECALL = 67,
    WBDI_DH_IS_READY_ECALL = 68,
    WBDI_DH_STATE_ECALL = 69,
    WBDI_DH_LOG_OCALL = 15,
    GOODIX_DH_MSG1_SIZE = 576,
    GOODIX_DH_MSG2_SIZE = 512,
    GOODIX_DH_MSG3_SIZE = 452,
    GOODIX_DH_TEST_PACKET_SIZE = 80,
    GOODIX_DH_TEST_PLAINTEXT_SIZE = 48,
    GOODIX_DH_STATE_PEER_ACCEPTED = 5,
    GOODIX_DH_STATE_READY = 7,
    GOODIX_DH_RELAY_HEADER_SIZE = 8,
    GOODIX_DH_RELAY_CAPACITY = 1024,
    GOODIX_DH_RELAY_PAYLOAD_CAPACITY = 1016
};

#define GOODIX_DH_UNWRITTEN_RESULT INT32_MIN
#define GOODIX_DH_RELAY_HELLO UINT32_C(0xd0d0d0d0)
#define GOODIX_DH_RELAY_MSG1 UINT32_C(0xd1d1d1d1)
#define GOODIX_DH_RELAY_MSG2 UINT32_C(0xd2d2d2d2)
#define GOODIX_DH_RELAY_MSG3 UINT32_C(0xd3d3d3d3)
#define GOODIX_DH_RELAY_TEST UINT32_C(0xdddddddd)

typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t output;
    uint32_t output_capacity;
    uint32_t padding1;
    uint64_t output_length;
} GoodixDhOutputMs;

typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t input;
    uint32_t input_length;
    uint32_t padding1;
    uint64_t output;
    uint32_t output_capacity;
    uint32_t padding2;
    uint64_t output_length;
} GoodixDhInOutMs;

typedef struct {
    int32_t result;
    uint32_t padding0;
    uint64_t input;
    uint32_t input_length;
    uint32_t padding1;
} GoodixDhInputMs;

/* These status ECALLs return the value itself, not a vendor error followed by
 * an output. Check their SGX status independently before consuming this field.
 */
typedef struct { uint32_t value; } GoodixDhStatusMs;

/* Logging has no return slot. A drop-only handler need not dereference strings. */
typedef struct {
    uint32_t level;
    uint32_t padding0;
    uint64_t filename;
    uint64_t function;
    uint32_t line;
    uint32_t padding1;
    uint64_t text;
} GoodixDhLogMs;

_Static_assert(sizeof(GoodixDhOutputMs) == 32, "DH output MS size");
_Static_assert(offsetof(GoodixDhOutputMs, output) == 8, "DH output pointer");
_Static_assert(offsetof(GoodixDhOutputMs, output_capacity) == 16, "DH capacity");
_Static_assert(offsetof(GoodixDhOutputMs, output_length) == 24, "DH length pointer");
_Static_assert(sizeof(GoodixDhInOutMs) == 48, "DH input/output MS size");
_Static_assert(offsetof(GoodixDhInOutMs, input) == 8, "DH input pointer");
_Static_assert(offsetof(GoodixDhInOutMs, input_length) == 16, "DH input length");
_Static_assert(offsetof(GoodixDhInOutMs, output) == 24, "DH output pointer");
_Static_assert(offsetof(GoodixDhInOutMs, output_capacity) == 32, "DH output capacity");
_Static_assert(offsetof(GoodixDhInOutMs, output_length) == 40, "DH length pointer");
_Static_assert(sizeof(GoodixDhInputMs) == 24, "DH input MS size");
_Static_assert(offsetof(GoodixDhInputMs, input) == 8, "DH input pointer");
_Static_assert(offsetof(GoodixDhInputMs, input_length) == 16, "DH input length");
_Static_assert(sizeof(GoodixDhStatusMs) == 4, "DH status MS size");
_Static_assert(sizeof(GoodixDhLogMs) == 40, "DH log MS size");
_Static_assert(offsetof(GoodixDhLogMs, filename) == 8, "DH log filename");
_Static_assert(offsetof(GoodixDhLogMs, function) == 16, "DH log function");
_Static_assert(offsetof(GoodixDhLogMs, line) == 24, "DH log line");
_Static_assert(offsetof(GoodixDhLogMs, text) == 32, "DH log text");

/* Callers must also clear the mapped output buffer and its uint32 length slot
 * before every call, then enforce the exact expected message size. This avoids
 * treating an unexecuted or partially completed call as a successful relay.
 */
static inline void goodix_dh_output_init(GoodixDhOutputMs *ms,
                                        uint64_t output, uint32_t capacity,
                                        uint64_t output_length)
{
    memset(ms, 0, sizeof(*ms));
    ms->result = GOODIX_DH_UNWRITTEN_RESULT;
    ms->output = output;
    ms->output_capacity = capacity;
    ms->output_length = output_length;
}

static inline void goodix_dh_inout_init(GoodixDhInOutMs *ms,
                                       uint64_t input, uint32_t input_length,
                                       uint64_t output, uint32_t capacity,
                                       uint64_t output_length)
{
    memset(ms, 0, sizeof(*ms));
    ms->result = GOODIX_DH_UNWRITTEN_RESULT;
    ms->input = input;
    ms->input_length = input_length;
    ms->output = output;
    ms->output_capacity = capacity;
    ms->output_length = output_length;
}

static inline void goodix_dh_input_init(GoodixDhInputMs *ms,
                                       uint64_t input, uint32_t length)
{
    memset(ms, 0, sizeof(*ms));
    ms->result = GOODIX_DH_UNWRITTEN_RESULT;
    ms->input = input;
    ms->input_length = length;
}

static inline int goodix_dh_output_complete(uint32_t sgx_status,
                                           int32_t vendor_result,
                                           uint32_t actual_length,
                                           uint32_t expected_length,
                                           uint32_t output_capacity)
{
    return sgx_status == 0 && vendor_result == 0 && expected_length != 0 &&
           actual_length == expected_length && actual_length <= output_capacity;
}

#endif
