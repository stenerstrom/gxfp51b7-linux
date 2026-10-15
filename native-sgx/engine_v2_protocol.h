/* SPDX-License-Identifier: MIT
 * Candidate original-Engine local protocol. All integers are little endian.
 * No raw images cross this interface. Status is positive errno or zero.
 */
#ifndef GXFP_ENGINE_V2_PROTOCOL_H
#define GXFP_ENGINE_V2_PROTOCOL_H
#include <stdint.h>
#include <stddef.h>

#define GXOE_VERSION 2U
#define GXOE_REQUEST_MAGIC "GXOE"
#define GXOE_RESPONSE_MAGIC "GXOR"
#define GXOE_SOCKET_PATH "/run/gxfp51b7-engine/reader.sock"
#define GXOE_TEMPLATE_MAX (4U * 1024U * 1024U)
#define GXOE_TEMPLATE_MIN 0x255U
#define GXOE_PAYLOAD_MAX (GXOE_TEMPLATE_MAX + 32U)
#define GXOE_PROFILE 12U
#define GXOE_TARGET_COUNT 20U
#define GXOE_ENROLL_MARKER "goodix-chicago-original-engine-v1"
#define GXOE_ENGINE_VERSION "Milan_v_3.02.00.15"
#define GXOE_TEMPLATE_SCHEMA 1U
#define GXOE_ENGINE_SHA256 "2bc1648bcc06c9f163d7c4bde62b8ecd145d22ad3941da7dd9fa4504bc3b175b"

enum GxoeOperation {
    GXOE_DESCRIBE = 1, GXOE_OPEN_SESSION = 2,
    GXOE_BEGIN_ENROLL = 3, GXOE_BEGIN_VERIFY = 4, GXOE_STEP = 5,
    GXOE_END_ACTION = 6, GXOE_CLOSE_SESSION = 7
};
enum GxoeEvent {
    GXOE_READY = 1, GXOE_WAIT_FINGER = 2, GXOE_WAIT_REMOVE = 3,
    GXOE_ENROLL_ACCEPTED = 4, GXOE_RETRY = 5, GXOE_ENROLL_COMPLETE = 6,
    GXOE_MATCH = 7, GXOE_NO_MATCH = 8, GXOE_CLOSED = 9
};
enum GxoeFlags {
    GXOE_ADAPTIVE_UPDATE_DISCARDED = 1U,
    GXOE_REQUIRES_EMPTY_START = 2U,
    GXOE_RETRY_SESSION_RETAINED = 4U
};

/* Requests have status=event=0. DESCRIBE/OPEN request session_id=0.
 * All remaining requests echo the OPEN response session_id. request_id must
 * be nonzero and strictly increase within a session. Replies echo both IDs
 * except OPEN assigns session_id. BEGIN_VERIFY carries only its sealed blob;
 * all other requests have empty payloads. CLOSE is acknowledged after cleanup.
 * A successful END_ACTION may return CLOSED with RETRY_SESSION_RETAINED only
 * after a nonfinal verification retry. That acknowledgement erases template
 * I/O and ends the action while retaining the paired worker and removal gate;
 * its remaining metadata must be zero. A completed decision never retains it.
 * CLOSE may use session_id=0 only to clean up a pending/failed OPEN belonging
 * to the same authenticated PID and process start time. It cannot close
 * another owner's session or bypass the monotonic request sequence.
 */
typedef struct {
    char magic[4];
    uint16_t version;
    uint16_t operation;
    uint32_t payload_length;
    uint32_t request_id;
    uint64_t session_id;
    int32_t status;
    uint32_t event;
} GxoeHeader;

/* Every successful reply carries this fixed metadata, then exactly blob_length
 * bytes only for ENROLL_COMPLETE. DESCRIBE uses target=20, quality=profile12,
 * coverage=template resource ceiling, flags=capability limitations. Other
 * metadata values are original numeric progress/hints/quality, or zero when
 * unavailable; they are never host-invented match thresholds.
 */
typedef struct {
    uint32_t used;
    uint32_t target;
    uint32_t progress;
    uint32_t hint;
    uint32_t quality;
    uint32_t coverage;
    uint32_t flags;
    uint32_t blob_length;
} GxoeMetadata;

_Static_assert(sizeof(GxoeHeader) == 32, "Original Engine header size");
_Static_assert(offsetof(GxoeHeader, session_id) == 16, "Session field offset");
_Static_assert(offsetof(GxoeHeader, status) == 24, "Status field offset");
_Static_assert(sizeof(GxoeMetadata) == 32, "Original Engine metadata size");
#endif
