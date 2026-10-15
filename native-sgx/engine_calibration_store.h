/* SPDX-License-Identifier: MIT
 * Bounded, RAM-only implementation of the original cold-start calibration
 * callbacks. This diagnostic store is erased on close and never persisted.
 */
#ifndef ENGINE_CALIBRATION_STORE_H
#define ENGINE_CALIBRATION_STORE_H
#include "engine_image_contract.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    unsigned char *data;
    int has_value;
    int failed;
    unsigned int reads, writes;
} EngineCalibrationStore;

static inline int engine_calibration_store_init(EngineCalibrationStore *store)
{
    memset(store, 0, sizeof(*store));
    store->data = calloc(1, ENGINE_CALIBRATION_BLOB_SIZE);
    if (!store->data) store->failed = 1;
    return store->failed ? -1 : 0;
}

static inline void engine_calibration_store_close(EngineCalibrationStore *store)
{
    if (store->data) {
        explicit_bzero(store->data, ENGINE_CALIBRATION_BLOB_SIZE);
        free(store->data);
    }
    memset(store, 0, sizeof(*store));
}

/* resolve validates complete spans inside the designated untrusted OCALL
 * arena. Neither enclave addresses nor arbitrary guest RAM are accepted.
 * A sticky host error is essential: original baseline code ignores the
 * marshaled callback result, so result0 alone cannot prove a valid operation.
 */
static inline int engine_calibration_store_io(EngineCalibrationStore *store,
                                              uint64_t index, uint64_t parameter,
                                              void *(*resolve)(uint64_t, size_t))
{
    EngineCalibrationMs *ms = resolve(parameter, sizeof(EngineCalibrationMs));
    if (!ms || !store->data || store->failed || index > 1) {
        store->failed = 1;
        return -1;
    }
    const uint64_t address = ms->buffer;
    const uint64_t length = ms->length;
    void *buffer = length == ENGINE_CALIBRATION_BLOB_SIZE ? resolve(address, (size_t)length) : NULL;
    /* Both resolved ranges are bounded before the non-overlap calculation. */
    if (!buffer || ms->kind != 0 ||
            (address < parameter + sizeof(*ms) && parameter < address + length)) {
        ms->result = -1;
        store->failed = 1;
        return -1;
    }
    if (index == 0) {
        if (store->has_value) memcpy(buffer, store->data, (size_t)length);
        else memset(buffer, 0, (size_t)length);
        store->reads++;
    } else {
        memcpy(store->data, buffer, (size_t)length);
        store->has_value = 1;
        store->writes++;
    }
    ms->result = 0;
    return 0;
}

#endif
