/* Offline control checks for whitelist-once and token-per-image ordering. */
#define main unused_wbdi_trial_main
#include "kvm_runner.c"
#undef main
#include "engine_pair_launch.h"
#include <assert.h>

static int calls[16], call_count, failure;
static uint8_t expected_measurement[32];
static uint8_t expected_signer[32];
static uint64_t expected_attributes[2];

static int fake_enter(uint64_t tcs, int call, uint64_t parameter)
{
    assert(tcs == 0x4019d000 && parameter == PARAMS);
    assert(call_count < 16);
    calls[call_count++] = call;
    if (call == 1) {
        struct whitelist_request *wl = (void *)(ram + parameter);
        assert(wl->certificate == PUBLIC_INPUT && wl->length > 0 && wl->length <= 65536);
        if (failure == 1) { wl->retval = 213; return 0; }
        if (failure == 2) return -1;
        wl->retval = 0;
        return 0;
    }
    assert(call == 0);
    struct token_request *request = (void *)(ram + parameter);
    assert(request->mrenclave == PARAMS + 64 && request->mrsigner == PARAMS + 96);
    assert(request->attributes == PARAMS + 128 && request->token == TOKEN);
    assert(!memcmp(ram + request->mrenclave, expected_measurement, 32));
    assert(!memcmp(ram + request->mrsigner, expected_signer, 32));
    assert(!memcmp(ram + request->attributes, expected_attributes, 16));
    for (unsigned int i = 0; i < 1024; i++) assert(ram[TOKEN + i] == 0);
    memset(ram + TOKEN, 0xa5, 1024); /* Synthetic token bytes never leave RAM. */
    if (failure == 3) { request->retval = 7; return 0; }
    if (failure == 4) return -1;
    if (failure != 5) request->retval = 0;
    return 0;
}

static void select_signature(uint8_t marker, const struct image *target)
{
    memset(ram + SIGNATURE, marker, 1808);
    memcpy(expected_measurement, ram + SIGNATURE + 960, 32);
    unsigned int size = 0;
    assert(EVP_Digest(ram + SIGNATURE + 128, 384, expected_signer,
                     &size, EVP_sha256(), NULL) && size == 32);
    expected_attributes[0] = target->attributes;
    expected_attributes[1] = target->xfrm;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    ram = calloc(1, RAM_SIZE);
    assert(ram);
    const struct image le = {.base = LE_BASE, .secs = EPC_BASE,
                             .first_tcs = 0x4019d000};
    const struct image wbdi = {.base = 0x42000000, .secs = EPC_BASE + PAGE,
                               .first_tcs = 0x4255a000, .attributes = 4, .xfrm = 3};
    const struct image engine = {.base = 0x44000000, .secs = EPC_BASE + 2*PAGE,
                                 .first_tcs = 0x44983000, .attributes = 4, .xfrm = 3};
    struct engine_pair_launch_state state = {0};
    select_signature(0x11, &wbdi);
    assert(!engine_pair_authorize(&state, &le, &wbdi, argv[1], fake_enter));
    select_signature(0x22, &engine);
    assert(!engine_pair_authorize(&state, &le, &engine, argv[1], fake_enter));
    assert(call_count == 3 && calls[0] == 1 && calls[1] == 0 && calls[2] == 0);
    assert(state.whitelist_registered && state.launch_tcs == le.first_tcs);

    struct image other_le = le;
    other_le.first_tcs += PAGE;
    assert(engine_pair_authorize(&state, &other_le, &engine, argv[1], fake_enter) == -1);
    assert(call_count == 3);

    for (failure = 1; failure <= 5; failure++) {
        state = (struct engine_pair_launch_state){0};
        call_count = 0;
        select_signature(0x33, &engine);
        assert(engine_pair_authorize(&state, &le, &engine, argv[1], fake_enter) == -1);
        assert(state.whitelist_registered == (failure >= 3));
        assert(call_count == (failure >= 3 ? 2 : 1));
        for (unsigned int i = 0; i < 1024; i++) assert(ram[TOKEN + i] == 0);
    }
    assert(engine_pair_authorize(NULL, &le, &engine, argv[1], fake_enter) == -1);
    assert(engine_pair_authorize(&state, &le, &le, argv[1], fake_enter) == -1);
    explicit_bzero(ram, RAM_SIZE);
    free(ram); ram = NULL;
    puts("{\"pair_launch_checks_passed\":true,\"authorization_sequence\":[1,0,0],\"hardware_used\":false}");
    return 0;
}
