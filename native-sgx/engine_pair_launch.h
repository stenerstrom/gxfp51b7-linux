/* SPDX-License-Identifier: MIT
 * Sequential launch authorization for two unchanged vendor enclaves.
 * Include after kvm_runner.c. Register the signed whitelist once per LE;
 * obtain a separate launch token for every target image.
 */
#ifndef ENGINE_PAIR_LAUNCH_H
#define ENGINE_PAIR_LAUNCH_H

struct engine_pair_launch_state {
    int whitelist_registered;
    uint64_t launch_tcs, launch_secs;
};

/* Call directly after load_image(target), while SIGNATURE still holds that
 * image's SIGSTRUCT. On success, EINIT the target before loading another
 * image. TOKEN is an SGX launch token in guest RAM, not a TPM object.
 * This helper must not run while another ECALL/OCALL is suspended.
 */
static int engine_pair_authorize(struct engine_pair_launch_state *state,
                                 const struct image *le,
                                 const struct image *target,
                                 const char *whitelist_path,
                                 int (*invoke_ecall)(uint64_t, int, uint64_t))
{
    explicit_bzero(ram + TOKEN, 1024);
    if (!state || !le || !target || !whitelist_path || !invoke_ecall ||
            le == target || !le->first_tcs || !le->secs ||
            !target->first_tcs || !target->secs ||
            le->first_tcs == target->first_tcs || le->secs == target->secs ||
            (state->whitelist_registered &&
             (state->launch_tcs != le->first_tcs || state->launch_secs != le->secs))) {
        fprintf(stderr, "pair_launch_state_invalid=1\n");
        return -1;
    }
    if (!state->whitelist_registered) {
        int fd = open(whitelist_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) return -1;
        struct stat st;
        if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 65536) {
            close(fd);
            return -1;
        }
        read_exact(fd, ram + PUBLIC_INPUT, (size_t)st.st_size);
        close(fd);
        memset(ram + PARAMS, 0, PAGE);
        struct whitelist_request *wl = (void *)(ram + PARAMS);
        wl->retval = UINT32_MAX;
        wl->certificate = PUBLIC_INPUT;
        wl->length = (uint32_t)st.st_size;
        int result = invoke_ecall(le->first_tcs, 1, PARAMS);
        printf("pair_le_whitelist_sgx_result=%d whitelist_result=0x%x\n", result, wl->retval);
        if (result || wl->retval) return -1;
        state->whitelist_registered = 1;
        state->launch_tcs = le->first_tcs;
        state->launch_secs = le->secs;
    }
    memset(ram + PARAMS, 0, PAGE);
    memcpy(ram + PARAMS + 64, ram + SIGNATURE + 960, 32);
    unsigned int hash_size = 0;
    if (!EVP_Digest(ram + SIGNATURE + 128, 384, ram + PARAMS + 96,
                    &hash_size, EVP_sha256(), NULL) || hash_size != 32)
        return -1;
    memcpy(ram + PARAMS + 128, &target->attributes, 8);
    memcpy(ram + PARAMS + 136, &target->xfrm, 8);
    struct token_request *request = (void *)(ram + PARAMS);
    request->retval = UINT32_MAX;
    request->mrenclave = PARAMS + 64;
    request->mrsigner = PARAMS + 96;
    request->attributes = PARAMS + 128;
    request->token = TOKEN;
    int result = invoke_ecall(le->first_tcs, 0, PARAMS);
    printf("pair_le_token_sgx_result=%d token_request_result=0x%x\n", result, request->retval);
    if (result || request->retval) {
        explicit_bzero(ram + TOKEN, 1024);
        return -1;
    }
    return 0;
}

#endif
