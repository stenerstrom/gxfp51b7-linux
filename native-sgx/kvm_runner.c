/* SPDX-License-Identifier: MIT
 * Experimental OS-free SGX loader. Physical EPC belongs exclusively to
 * Linux's existing sgx_vepc allocator; no competing kernel driver is used.
 * The launcher opens EPC and permanently drops privilege before exec.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <openssl/evp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>
#include "../sgx-vm/chicago_crc.h"

#define PAGE 4096ULL
#define RAM_SIZE (32ULL << 20)
#define EPC_SIZE (32ULL << 20)
#define EPC_BASE 0x10000000ULL
#define CODE_BASE 0x100000ULL
#define CONTROL 0x60000ULL
#define SOURCE 0x300000ULL
#define PAGEINFO 0x301000ULL
#define SECINFO 0x301040ULL
#define SIGNATURE 0x302000ULL
#define TOKEN 0x303000ULL
#define PARAMS 0x304000ULL
#define PUBLIC_INPUT 0x308000ULL
#define SEALED_INPUT 0x31a000ULL
#define CAPTURE_OUTPUT 0x320000ULL
#define LE_BASE 0x40000000ULL
#define GOODIX_BASE 0x42000000ULL

/* Existing probes keep their 64 KiB outside stack. A separately built image
 * probe may select the reviewed 1 MiB arena for the original Engine's large
 * calibration OCALL. Neither arena overlaps guest code or staging memory.
 */
#ifndef KVM_OUTSIDE_STACK_BOTTOM
#define KVM_OUTSIDE_STACK_BOTTOM 0x70000ULL
#endif
#ifndef KVM_OUTSIDE_STACK_TOP
#define KVM_OUTSIDE_STACK_TOP 0x80000ULL
#endif
_Static_assert(KVM_OUTSIDE_STACK_BOTTOM < KVM_OUTSIDE_STACK_TOP,
               "outside stack must have a positive size");
_Static_assert(!(KVM_OUTSIDE_STACK_BOTTOM & (PAGE - 1)) &&
               !(KVM_OUTSIDE_STACK_TOP & (PAGE - 1)),
               "outside stack bounds must be page aligned");
_Static_assert(KVM_OUTSIDE_STACK_TOP <= RAM_SIZE,
               "outside stack must remain inside guest RAM");
_Static_assert(KVM_OUTSIDE_STACK_BOTTOM >= CONTROL + PAGE &&
               KVM_OUTSIDE_STACK_TOP <= SOURCE &&
               (KVM_OUTSIDE_STACK_TOP <= CODE_BASE ||
                KVM_OUTSIDE_STACK_BOTTOM >= CODE_BASE + 0x80000ULL),
               "outside stack overlaps control, guest-code reservation, or staging");
_Static_assert((KVM_OUTSIDE_STACK_BOTTOM >= 0x70000ULL &&
                KVM_OUTSIDE_STACK_TOP <= 0x80000ULL) ||
               (KVM_OUTSIDE_STACK_BOTTOM >= 0x180000ULL &&
                KVM_OUTSIDE_STACK_TOP <= 0x280000ULL),
               "outside stack must use a reviewed arena away from control, code, and staging");

extern unsigned char _binary_vm_guest_bin_start[], _binary_vm_guest_bin_end[];
static uint8_t *ram;
static int cpu_fd = -1;
static struct kvm_run *run;
static unsigned int next_epc, next_table = 0x20000;
static struct kvm_sregs baseline;
static volatile sig_atomic_t timed_out;
static uint64_t ocall_counts[16];
static uint32_t pmk_success_length, unseal_error;
static uint32_t encrypted_bios_length;
static int transport_fd = -1;
static uint32_t tls_connected_count, tls_invalid_mac_count, tls_last_state;
static uint32_t bridge_crc_ok, bridge_crc_bad;
static uint32_t image_ready_count, image_crc_ok, image_crc_bad;
static int capture_enabled;

struct plan_header {
    char magic[8];
    uint64_t size, ssa_size, tcs, attributes, xfrm, count, entry;
};
struct plan_page {
    uint64_t offset, flags, measured, reserved;
    uint8_t data[4096];
};
struct image {
    uint64_t base, secs, first_tcs, count, attributes, xfrm;
};
struct control {
    uint64_t leaf, rbx, rcx, rdx, result, flags, measured, secs;
    uint64_t outside_stack, outside_frame, asynchronous_exits;
};
_Static_assert(sizeof(struct plan_header) == 64, "plan header layout");
_Static_assert(sizeof(struct plan_page) == 4128, "plan page layout");

/* Standard 64-bit edger8r marshalling for launch_enclave.edl. */
struct whitelist_request {
    uint32_t retval, padding;
    uint64_t certificate;
    uint32_t length, padding2;
};
struct token_request {
    uint32_t retval, padding;
    uint64_t mrenclave, mrsigner, attributes, token;
};
_Static_assert(sizeof(struct whitelist_request) == 24, "whitelist request layout");
_Static_assert(sizeof(struct token_request) == 40, "token request layout");
struct me_request {
    int32_t retval;
    uint32_t padding;
    uint64_t buffer;
    uint16_t capacity;
    uint8_t padding2[6];
    uint64_t length;
};
_Static_assert(sizeof(struct me_request) == 32, "Goodix ME OCALL layout");
struct tls_io_request {
    int32_t retval;
    uint32_t padding;
    uint64_t context, buffer, length;
};
_Static_assert(sizeof(struct tls_io_request) == 32, "Goodix TLS OCALL layout");
struct image_init_request {
    int32_t retval;
    uint32_t padding;
    uint64_t image_length, nav_length, sensor_type;
    uint32_t retries, retry_limit;
};
_Static_assert(sizeof(struct image_init_request) == 40, "Goodix image init layout");

static void timeout_handler(int sig)
{
    (void)sig;
    timed_out = 1;
    if (run) run->immediate_exit = 1;
}

static void fail(const char *name)
{
    fprintf(stderr, "%s: %s\n", name, strerror(errno));
    exit(1); /* FD closure returns EPC via the kernel's owning allocator. */
}

static void check_ioctl(int fd, unsigned long request, void *argument, const char *name)
{
    if (ioctl(fd, request, argument) < 0) fail(name);
}

static void read_exact(int fd, void *data, size_t size)
{
    uint8_t *p = data;
    while (size) {
        ssize_t n = read(fd, p, size);
        if (n <= 0) { errno = EIO; fail("read public enclave plan"); }
        p += n;
        size -= (size_t)n;
    }
}

static int rpc_read_exact(void *data, size_t size)
{
    uint8_t *p = data;
    while (size && !timed_out) {
        ssize_t n = read(transport_fd, p, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return size ? -1 : 0;
}

static int rpc_write_exact(const void *data, size_t size)
{
    const uint8_t *p = data;
    while (size && !timed_out) {
        ssize_t n = send(transport_fd, p, size, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return size ? -1 : 0;
}

static int bridge_call(uint8_t operation, const void *input, uint32_t size,
                       void *output, uint32_t capacity, uint32_t *received)
{
    uint8_t request[12] = {'G', 'X', 'T', 'L', operation}, reply[12];
    *received = 0;
    if (transport_fd < 0) return ENOTCONN;
    memcpy(request + 8, &size, 4);
    if (rpc_write_exact(request, 12) || (size && rpc_write_exact(input, size)) ||
            rpc_read_exact(reply, 12) || memcmp(reply, "GXTR", 4)) return EIO;
    uint32_t length;
    int32_t status;
    memcpy(&status, reply + 4, 4);
    memcpy(&length, reply + 8, 4);
    if (length > capacity || (length && rpc_read_exact(output, length))) return EIO;
    *received = length;
    return status;
}

static void map_page(uint64_t linear, uint64_t physical, uint64_t flags)
{
    uint64_t *pdpt = (uint64_t *)(ram + 0x2000);
    unsigned int pdpt_index = (unsigned int)(linear >> 30);
    if (pdpt_index > 1) { errno = EINVAL; fail("page table range"); }
    uint64_t *pd = (uint64_t *)(ram + (pdpt[pdpt_index] & 0xfffff000));
    unsigned int pdi = (unsigned int)((linear >> 21) & 511);
    if (!pd[pdi]) {
        if (next_table + PAGE >= CONTROL) { errno = ENOMEM; fail("page table bound"); }
        pd[pdi] = next_table | 7;
        next_table += PAGE;
    }
    if (pd[pdi] & 0x80) { errno = EINVAL; fail("huge page overlap"); }
    uint64_t *pt = (uint64_t *)(ram + (pd[pdi] & 0xfffff000));
    pt[(linear >> 12) & 511] = physical | flags;
}

static uint64_t allocate_epc(void)
{
    if (next_epc >= EPC_SIZE / PAGE) { errno = ENOMEM; fail("EPC bound"); }
    return EPC_BASE + PAGE * next_epc++;
}

static struct kvm_segment segment(unsigned int selector, unsigned int type, unsigned int dpl, int code)
{
    struct kvm_segment s = {0};
    s.selector = (uint16_t)selector;
    s.type = (uint8_t)type;
    s.dpl = (uint8_t)dpl;
    s.present = 1;
    s.s = 1;
    s.l = (uint8_t)code;
    s.db = (uint8_t)!code;
    s.g = 1;
    s.limit = 0xffffffff;
    return s;
}

static int outside_resume_valid(uint64_t stack, uint64_t frame)
{
    return stack >= KVM_OUTSIDE_STACK_BOTTOM && stack <= KVM_OUTSIDE_STACK_TOP &&
           (!frame || (frame >= KVM_OUTSIDE_STACK_BOTTOM && frame <= KVM_OUTSIDE_STACK_TOP));
}

static int execute(int user)
{
    struct control *ctl = (void *)(ram + CONTROL);
    struct kvm_sregs sregs = baseline;
    struct kvm_regs regs = {.rip = CODE_BASE + (user ? 0x100 : 0),
                            .rsp = user ? KVM_OUTSIDE_STACK_TOP : 0x80000,
                            .rflags = user ? 0x3002 : 2};
    if (user) {
        if (ctl->outside_stack) {
            if (!outside_resume_valid(ctl->outside_stack, ctl->outside_frame)) {
                fprintf(stderr, "untrusted_stack_out_of_bounds=1\n");
                return -1;
            }
            regs.rsp = ctl->outside_stack;
            regs.rbp = ctl->outside_frame;
        }
        sregs.cs = segment(0x1b, 11, 3, 1);
        sregs.ss = sregs.ds = sregs.es = segment(0x23, 3, 3, 0);
        sregs.fs = sregs.gs = sregs.ds;
    }
    check_ioctl(cpu_fd, KVM_SET_SREGS, &sregs, "KVM_SET_SREGS");
    check_ioctl(cpu_fd, KVM_SET_REGS, &regs, "KVM_SET_REGS");
    for (unsigned int exits = 0; exits < 16; exits++) {
        if (timed_out) return -1;
        if (ioctl(cpu_fd, KVM_RUN, 0) < 0) {
            if (errno == EINTR && !timed_out) continue;
            fail("KVM_RUN");
        }
        if (run->exit_reason == KVM_EXIT_IO && run->io.direction == KVM_EXIT_IO_OUT &&
                run->io.port == 0xf1 && run->io.size == 1 && run->io.count == 1) {
            struct control *c = (struct control *)(ram + CONTROL);
            if (c->measured == 0x100 || (user && c->measured == 1)) {
                fprintf(stderr, "guest_fault=%s error=0x%llx\n", user ? "AEX" : "exception",
                        (unsigned long long)c->result);
                return -1;
            }
            return 0;
        }
        if (run->exit_reason == KVM_EXIT_INTR) continue;
        fprintf(stderr, "unexpected_kvm_exit=%u\n", run->exit_reason);
        return -1;
    }
    return -1;
}

static int encls(uint64_t leaf, uint64_t b, uint64_t c, uint64_t d, int measured, uint64_t secs)
{
    struct control *ctl = (struct control *)(ram + CONTROL);
    *ctl = (struct control){.leaf = leaf, .rbx = b, .rcx = c, .rdx = d,
                            .measured = (uint64_t)measured, .secs = secs};
    if (execute(0)) return -1;
    /* ECREATE/EADD/EEXTEND signal faults, not a defined return in EAX. */
    return leaf == 2 || leaf == 3 ? (int)ctl->result : 0;
}

/* EINIT may yield to a pending IRQ/NMI/SMI with SGX_UNMASKED_EVENT (128).
 * Retry only that status, using Linux's 20-attempt/50-batch/20ms limits.
 * Signature, token, measurement and other SGX errors remain final errors.
 */
enum { EINIT_UNMASKED_EVENT = 128, EINIT_BATCH_ATTEMPTS = 20, EINIT_BATCHES = 50 };

static int retry_enclave_init(int (*attempt)(void *), int (*pause)(void *),
                             void *context, unsigned int *retries)
{
    *retries = 0;
    for (unsigned int batch = 0; batch < EINIT_BATCHES; batch++) {
        for (unsigned int item = 0; item < EINIT_BATCH_ATTEMPTS; item++) {
            if (timed_out) return -1;
            int status = attempt(context);
            if (status != EINIT_UNMASKED_EVENT) return status;
            (*retries)++;
        }
        if (batch + 1 < EINIT_BATCHES && pause(context)) return -1;
    }
    return EINIT_UNMASKED_EVENT;
}

static int enclave_init_attempt(void *context)
{
    return encls(2, SIGNATURE, *(uint64_t *)context, TOKEN, 0, 0);
}

static int enclave_init_pause(void *context)
{
    (void)context;
    struct timespec delay = {.tv_nsec = 20000000};
    while (nanosleep(&delay, &delay)) {
        if (errno != EINTR || timed_out) return -1;
    }
    return 0;
}

static int initialize_enclave(uint64_t secs, unsigned int *retries)
{
    return retry_enclave_init(enclave_init_attempt, enclave_init_pause, &secs, retries);
}

static int enter(uint64_t tcs, int call, uint64_t parameter)
{
    struct control *ctl = (struct control *)(ram + CONTROL);
    *ctl = (struct control){.leaf = (uint64_t)(int64_t)call, .rbx = tcs, .rdx = parameter};
    if (execute(1)) return -1;
    printf("ecall_number=%d return_call=%lld sgx_result=0x%llx asynchronous_exits=%llu\n", call,
           (long long)ctl->flags, (unsigned long long)ctl->result,
           (unsigned long long)ctl->asynchronous_exits);
    return ctl->flags == UINT64_MAX && ctl->result == 0 ? 0 : -1;
}

static void *outside_pointer(uint64_t address, size_t length)
{
    /* OCALL marshalling uses only the selected private outside-stack arena.
     * No enclave pointer is ever cast to a host pointer.
     */
    if (address < KVM_OUTSIDE_STACK_BOTTOM || address > KVM_OUTSIDE_STACK_TOP ||
            length > KVM_OUTSIDE_STACK_TOP - address)
        return NULL;
    return ram + address;
}

static uint32_t filtered_scalar(uint64_t address, const char *prefix, uint32_t bound)
{
    const char *s = outside_pointer(address, 1);
    if (!s) return 0;
    size_t available = (size_t)(KVM_OUTSIDE_STACK_TOP - address);
    if (available > 4096) available = 4096;
    const char *end = memchr(s, 0, available);
    size_t prefix_length = strlen(prefix);
    if (!end || (size_t)(end - s) <= prefix_length || memcmp(s, prefix, prefix_length)) return 0;
    s += prefix_length;
    uint32_t value = 0;
    unsigned int digits = 0;
    while (s < end && *s >= '0' && *s <= '9') {
        uint32_t digit = (uint32_t)(*s++ - '0');
        if (++digits > 10 || value > bound / 10 || value * 10 + digit > bound) return 0;
        value = value * 10 + digit;
    }
    return digits ? value : 0;
}

static int filtered_message_is(uint64_t address, const char *prefix)
{
    size_t length = strlen(prefix);
    const char *s = outside_pointer(address, length + 1);
    return s && !memcmp(s, prefix, length);
}

static uint32_t dispatch_ocall(uint64_t index, uint64_t parameter)
{
    if (index >= 16) return 0x1001;
    ocall_counts[index]++;
    if (index == 14) {
        const uint64_t *log = outside_pointer(parameter, 40);
        if (!log) return 2;
        /* Original messages can contain secrets. Never print a string.
         * Only these two known, tightly bounded scalar fields are read.
         */
        uint32_t length = filtered_scalar(log[4], "get pmk success len ", 100);
        uint32_t error = filtered_scalar(log[4], "TLS_Unseal_enclave sgx_unseal_data failed ret:", 0x7fffffff);
        if (length) pmk_success_length = length;
        if (error) unseal_error = error;
        if (filtered_message_is(log[4], "data_from_device_ecall crc check ok")) image_crc_ok++;
        if (filtered_message_is(log[4], "data_from_device_ecall crc check failed")) image_crc_bad++;
        return 0;
    }
    if (index == 6 || index == 7) {
        struct me_request *me = outside_pointer(parameter, sizeof(*me));
        /* The original enclave supplies a 4096-byte cache/ME buffer even
         * though this machine's encrypted BIOS container is only 885 bytes.
         */
        if (!me || me->capacity > 4096) return 2;
        uint16_t *length = outside_pointer(me->length, 2);
        uint8_t *buffer = me->capacity ? outside_pointer(me->buffer, me->capacity) : NULL;
        if (!length || (me->capacity && !buffer)) return 2;
        *length = index == 6 ? (uint16_t)encrypted_bios_length : 0;
        me->retval = 0x100001;
        if (index == 6 && encrypted_bios_length && me->capacity >= encrypted_bios_length) {
            memcpy(buffer, ram + SEALED_INPUT, encrypted_bios_length);
            me->retval = 0;
        }
        return 0;
    }
    if (index == 8) {
        int32_t *retval = outside_pointer(parameter, 4);
        if (!retval) return 2;
        *retval = 0; /* No persistent host key cache is created or changed. */
        return 0;
    }
    if ((index == 0 || index == 1) && transport_fd >= 0) {
        struct tls_io_request *io = outside_pointer(parameter, sizeof(*io));
        if (!io || !io->length || io->length > 0x7000) return 2;
        uint8_t *buffer = outside_pointer(io->buffer, (size_t)io->length);
        if (!buffer) return 2;
        uint32_t n = 0;
        int status;
        if (index == 0) {
            uint8_t reply[1028] = {0};
            uint32_t wanted = (uint32_t)io->length;
            status = bridge_call(3, &wanted, 4, reply, sizeof(reply), &n);
            if (!status) {
                uint32_t crc;
                if (n >= 5) memcpy(&crc, reply + n - 4, 4);
                else crc = 0;
                if (n < 5 || n - 4 > io->length || crc32(0, reply, n - 4) != crc) {
                    bridge_crc_bad++; status = EIO;
                } else {
                    bridge_crc_ok++; n -= 4;
                    memcpy(buffer, reply, n);
                }
            }
            explicit_bzero(reply, sizeof(reply));
            io->retval = status == ETIMEDOUT ? -0x6900 : status ? -1 : (int32_t)n;
        } else {
            if (io->length < 5 || io->length > 4092) return 2;
            status = bridge_call(2, buffer, (uint32_t)io->length, NULL, 0, &n);
            io->retval = status ? -1 : (int32_t)io->length;
        }
        return 0;
    }
    if (index == 9) {
        const uint32_t *state = outside_pointer(parameter, 4);
        if (!state) return 2;
        tls_last_state = *state;
        return 0;
    }
    if (index == 10) { tls_invalid_mac_count++; return 0; }
    if (index == 11) { tls_connected_count++; return 0; }
    if (capture_enabled && index == 4) { image_ready_count++; return 0; }
    if (capture_enabled && index == 15) return 0; /* Discard original binary diagnostics. */
    fprintf(stderr, "unsupported_ocall_index=%llu\n", (unsigned long long)index);
    return 0x1001;
}

static int goodix_call(uint64_t tcs, int call, uint64_t parameter)
{
    struct control *ctl = (void *)(ram + CONTROL);
    *ctl = (struct control){.leaf = (uint64_t)(int64_t)call, .rbx = tcs, .rdx = parameter};
    unsigned int count = 0;
    for (; count < 4096; count++) {
        if (execute(1)) return -1;
        if (ctl->flags == UINT64_MAX) {
            printf("goodix_ecall_number=%d sgx_result=0x%llx ocalls=%u\n", call,
                   (unsigned long long)ctl->result, count);
            return ctl->result ? -1 : 0;
        }
        uint32_t status = dispatch_ocall(ctl->flags, ctl->result);
        uint64_t outside_stack = ctl->outside_stack, outside_frame = ctl->outside_frame;
        *ctl = (struct control){.leaf = (uint64_t)(int64_t)-2, .rbx = tcs, .rdx = status,
                                .outside_stack = outside_stack, .outside_frame = outside_frame};
    }
    fprintf(stderr, "ocall_limit_reached=1\n");
    return -1;
}

static uint64_t conservative_cpu_features(void)
{
    unsigned int a, b, c, d;
    if (!__get_cpuid(1, &a, &b, &c, &d)) { errno = ENOTSUP; fail("CPUID features"); }
    const unsigned int legacy = (1U << 0) | (1U << 15) | (1U << 23) |
                                (1U << 24) | (1U << 25) | (1U << 26);
    const unsigned int sse4 = (1U << 0) | (1U << 9) | (1U << 19) | (1U << 20);
    if ((d & legacy) != legacy || (c & sse4) != sse4) {
        errno = ENOTSUP; fail("required verified SSE features");
    }
    /* Wintel CPU-feature bits 0..10: through SSE4.2, all verified above.
     * The newer LE rejects a feature set lacking bits above SSE3.
     * No AVX is advertised with the conservative enclave XFRM=3.
     */
    return 0x7ff;
}

static int load_image(const char *path, uint64_t base, struct image *image)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open public enclave plan");
    struct stat st;
    if (fstat(fd, &st)) fail("stat enclave plan");
    struct plan_header h;
    read_exact(fd, &h, sizeof(h));
    if (memcmp(h.magic, "B7SGX001", 8) || h.size < PAGE || h.size > (32ULL << 20) ||
            (h.size & (h.size - 1)) || (base & (h.size - 1)) || h.ssa_size != 1 ||
            h.xfrm != 3 || !h.count || h.count >= EPC_SIZE / PAGE ||
            h.tcs >= h.size || (h.tcs & (PAGE - 1)) ||
            (uint64_t)st.st_size != PAGE + h.count * sizeof(struct plan_page)) {
        errno = EINVAL; fail("validate enclave plan");
    }
    uint8_t header_tail[4096 - 64];
    read_exact(fd, header_tail, sizeof(header_tail));
    memcpy(ram + SIGNATURE, header_tail, 1808);
    image->base = base;
    image->secs = allocate_epc();
    image->first_tcs = base + h.tcs;
    image->count = h.count;
    image->attributes = h.attributes;
    image->xfrm = h.xfrm;
    memset(ram + SOURCE, 0, PAGE);
    memcpy(ram + SOURCE, &h.size, 8);
    memcpy(ram + SOURCE + 8, &base, 8);
    uint32_t ssa_size = (uint32_t)h.ssa_size;
    memcpy(ram + SOURCE + 16, &ssa_size, 4);
    memcpy(ram + SOURCE + 48, &h.attributes, 8);
    memcpy(ram + SOURCE + 56, &h.xfrm, 8);
    uint64_t *pi = (uint64_t *)(ram + PAGEINFO);
    memset(pi, 0, 32);
    pi[1] = SOURCE;
    pi[2] = SECINFO;
    memset(ram + SECINFO, 0, 64);
    int status = encls(0, PAGEINFO, image->secs, 0, 0, 0);
    printf("enclave_base=0x%llx ecreate_result=%d\n", (unsigned long long)base, status);
    if (status) { close(fd); return status; }
    uint64_t previous = UINT64_MAX;
    for (uint64_t index = 0; index < h.count; index++) {
        struct plan_page p;
        read_exact(fd, &p, sizeof(p));
        if (p.offset >= h.size || (p.offset & (PAGE - 1)) ||
                (previous != UINT64_MAX && p.offset <= previous) || p.measured > 1 ||
                p.reserved || (p.flags != 0x100 && (p.flags & ~7ULL) != 0x200)) {
            errno = EINVAL; fail("validate enclave page");
        }
        previous = p.offset;
        uint64_t phys = allocate_epc();
        map_page(base + p.offset, phys, 7); /* EPCM retains signed R/W/X flags. */
        memcpy(ram + SOURCE, p.data, PAGE);
        memset(ram + SECINFO, 0, 64);
        memcpy(ram + SECINFO, &p.flags, 8);
        pi[0] = base + p.offset;
        pi[1] = SOURCE;
        pi[2] = SECINFO;
        pi[3] = image->secs;
        status = encls(1, PAGEINFO, base + p.offset, 0, (int)p.measured, image->secs);
        if (status) { close(fd); return status; }
    }
    close(fd);
    printf("enclave_loaded_pages=%llu\n", (unsigned long long)h.count);
    return 0;
}

static int authorize_goodix(const struct image *le, const struct image *goodix,
                            const char *whitelist_path)
{
    int fd = open(whitelist_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("open signed vendor whitelist");
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 65536) {
        errno = EINVAL; fail("signed whitelist size");
    }
    read_exact(fd, ram + PUBLIC_INPUT, (size_t)st.st_size);
    close(fd);
    memset(ram + PARAMS, 0, PAGE);
    struct whitelist_request *wl = (void *)(ram + PARAMS);
    wl->certificate = PUBLIC_INPUT;
    wl->length = (uint32_t)st.st_size;
    int result = enter(le->first_tcs, 1, PARAMS);
    printf("intel_le_whitelist_sgx_result=%d whitelist_result=0x%x\n", result, wl->retval);
    if (result || wl->retval) return -1;

    memset(ram + PARAMS, 0, PAGE);
    memcpy(ram + PARAMS + 64, ram + SIGNATURE + 960, 32);
    unsigned int hash_size = 0;
    if (!EVP_Digest(ram + SIGNATURE + 128, 384, ram + PARAMS + 96,
                    &hash_size, EVP_sha256(), NULL) || hash_size != 32) {
        errno = EINVAL; fail("hash public Goodix signing modulus");
    }
    memcpy(ram + PARAMS + 128, &goodix->attributes, 8);
    memcpy(ram + PARAMS + 136, &goodix->xfrm, 8);
    memset(ram + TOKEN, 0, 1024);
    struct token_request *request = (void *)(ram + PARAMS);
    request->mrenclave = PARAMS + 64;
    request->mrsigner = PARAMS + 96;
    request->attributes = PARAMS + 128;
    request->token = TOKEN;
    result = enter(le->first_tcs, 0, PARAMS);
    printf("intel_le_token_sgx_result=%d token_request_result=0x%x\n", result, request->retval);
    if (result || request->retval) return -1;
    /* The launch token stays in anonymous RAM and is never logged or saved. */
    return 0;
}

static int initialize_runtime(const struct image *image)
{
    memset(ram + PARAMS, 0, PAGE);
    *(uint64_t *)(ram + PARAMS) = conservative_cpu_features();
    *(uint64_t *)(ram + PARAMS + 16) = 1ULL << 63;
    return enter(image->first_tcs, -1, PARAMS);
}

static double monotonic_seconds(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) fail("monotonic clock");
    return now.tv_sec + now.tv_nsec / 1e9;
}

static int sensor_handshake(const struct image *image)
{
    uint32_t received = 0;
    int result = bridge_call(1, NULL, 0, NULL, 0, &received);
    printf("tls_bridge_start_result=%d\n", result);
    if (result) return -1;
    double deadline = monotonic_seconds() + 25;
    for (unsigned int reads = 0; reads < 120 && monotonic_seconds() < deadline &&
            !tls_connected_count && !tls_invalid_mac_count; reads++) {
        *(int32_t *)(ram + PARAMS) = -1;
        result = goodix_call(image->first_tcs, 0x29, PARAMS);
        int32_t retval = *(int32_t *)(ram + PARAMS);
        printf("tls_read_result=%d tls_state=%u\n", retval, tls_last_state);
        if (result || (retval < 0 && retval != -0x6900 && retval != -0x6880)) return -1;
    }
    int32_t sensor_connected = 0;
    if (tls_connected_count && !tls_invalid_mac_count)
        result = bridge_call(4, NULL, 0, &sensor_connected, 4, &received);
    else result = -1;
    printf("tls_connected_callbacks=%u invalid_mac_callbacks=%u sensor_connected_flag=%d\n",
           tls_connected_count, tls_invalid_mac_count, sensor_connected);
    printf("tls_rx_ocalls=%llu tls_tx_ocalls=%llu bridge_crc_ok=%u bridge_crc_bad=%u\n",
           (unsigned long long)ocall_counts[0], (unsigned long long)ocall_counts[1],
           bridge_crc_ok, bridge_crc_bad);
    return result || received != 4 || sensor_connected != 1 || bridge_crc_bad ? -1 : 0;
}

static int initialize_images(const struct image *image)
{
    memset(ram + PARAMS, 0, PAGE);
    struct image_init_request *request = (void *)(ram + PARAMS);
    request->retval = -1;
    request->image_length = PARAMS + 64;
    request->nav_length = PARAMS + 66;
    request->sensor_type = PARAMS + 68;
    request->retry_limit = 1;
    *(uint16_t *)(ram + PARAMS + 64) = 10240;
    *(uint16_t *)(ram + PARAMS + 66) = 3200;
    *(uint32_t *)(ram + PARAMS + 68) = 12;
    int result = goodix_call(image->first_tcs, 2, PARAMS);
    printf("image_init_result=%d goodix_result=0x%x\n", result, (uint32_t)request->retval);
    if (result || request->retval) return -1;
    memset(ram + PARAMS, 0, PAGE);
    ((uint64_t *)(ram + PARAMS))[0] = PARAMS + 64;
    ((uint64_t *)(ram + PARAMS))[1] = PARAMS + 72;
    result = goodix_call(image->first_tcs, 0x23, PARAMS);
    uint64_t image_size = *(uint64_t *)(ram + PARAMS + 64);
    uint64_t base_size = *(uint64_t *)(ram + PARAMS + 72);
    printf("image_size=%llu imagebase_size=%llu\n",
           (unsigned long long)image_size, (unsigned long long)base_size);
    return result || image_size != 20544 || base_size != 10272 ? -1 : 0;
}

static int sensor_capture(const struct image *image)
{
    uint32_t received = 0;
    int result = bridge_call(6, NULL, 0, NULL, 0, &received);
    printf("native_capture_request_result=%d\n", result);
    if (result) return -1;
    double deadline = monotonic_seconds() + 12;
    uint32_t authenticated_bytes = 0;
    for (unsigned int reads = 0; reads < 64 &&
            monotonic_seconds() < deadline && !tls_invalid_mac_count; reads++) {
        *(int32_t *)(ram + PARAMS) = -1;
        result = goodix_call(image->first_tcs, 0x29, PARAMS);
        int32_t retval = *(int32_t *)(ram + PARAMS);
        printf("native_capture_read_result=%d\n", retval);
        if (result || (retval < 0 && retval != -0x6900 && retval != -0x6880)) return -1;
        if (retval > 0) { authenticated_bytes = (uint32_t)retval; break; }
    }
    /* The original one-key callback is not emitted for these source images
     * (also observed in the Windows V6/V7 probes). Positive authenticated
     * TLS delivery plus the independently checked exported packet are the
     * completion conditions; no readiness flag is fabricated.
     */
    printf("native_image_authenticated_plaintext_bytes=%u\n", authenticated_bytes);
    if (!authenticated_bytes || image_crc_bad || tls_invalid_mac_count) return -1;
    memset(ram + PARAMS, 0, PAGE);
    *(uint64_t *)(ram + PARAMS) = CAPTURE_OUTPUT;
    *(uint16_t *)(ram + PARAMS + 8) = 10564;
    memset(ram + CAPTURE_OUTPUT, 0, 10564);
    result = goodix_call(image->first_tcs, 0x15, PARAMS);
    int crc_valid = chicago_packet_valid(ram + CAPTURE_OUTPUT, 10564);
    printf("native_source_export_result=%d image_crc_valid=%d image_ready_callbacks=%u\n",
           result, crc_valid, image_ready_count);
    if (!result && crc_valid)
        result = bridge_call(7, ram + CAPTURE_OUTPUT, 10564, NULL, 0, &received);
    else result = -1;
    explicit_bzero(ram + CAPTURE_OUTPUT, 10564);
    printf("native_capture_host_result=%d source_packet_erased=1 raw_image_logged=0\n", result);
    return result;
}

#ifdef GXFP_PERSISTENT_CAPTURE
/* One Linux enclave/TLS session, driven by the same bounded host RPC as the
 * original session prototype. The finished driver still uses option 0/1. */
static int sensor_capture_session(const struct image *image)
{
    double deadline = monotonic_seconds() + 1200;
    for (unsigned int count = 0; count <= 512; count++) {
        double remaining = deadline - monotonic_seconds();
        if (remaining <= 0) return -1;
        unsigned int wait_seconds = remaining < 125 ? (unsigned int)remaining + 1 : 125;
        struct timeval waiting = {.tv_sec = wait_seconds};
        struct timeval active = {.tv_sec = 5};
        if (setsockopt(transport_fd, SOL_SOCKET, SO_RCVTIMEO, &waiting, sizeof(waiting))) return -1;
        alarm(wait_seconds + 1);
        uint32_t next = 0, received = 0;
        int result = bridge_call(8, NULL, 0, &next, sizeof(next), &received);
        if (setsockopt(transport_fd, SOL_SOCKET, SO_RCVTIMEO, &active, sizeof(active))) return -1;
        alarm(30);
        if (result || received != sizeof(next)) return -1;
        if (next == 2) {
            printf("native_session_frames=%u clean_finish=1\n", count);
            return 0;
        }
        if (next != 1 || count == 512) return -1;
        image_ready_count = image_crc_ok = image_crc_bad = 0;
        if (sensor_capture(image)) return -1;
    }
    return -1;
}
#endif

static void setup_vm(int kvm_fd, int epc_fd, int *vm_fd, void **epc, size_t *run_size)
{
    *vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
    if (*vm_fd < 0) fail("KVM_CREATE_VM");
    if (ioctl(*vm_fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) fail("KVM_SET_TSS_ADDR");
    ram = mmap(NULL, RAM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    *epc = mmap(NULL, EPC_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, epc_fd, 0);
    if (ram == MAP_FAILED || *epc == MAP_FAILED) fail("map VM memory");
    (void)madvise(ram, RAM_SIZE, MADV_DONTDUMP);
    struct kvm_userspace_memory_region region = {.slot = 0, .guest_phys_addr = 0,
                                                .memory_size = RAM_SIZE, .userspace_addr = (uintptr_t)ram};
    check_ioctl(*vm_fd, KVM_SET_USER_MEMORY_REGION, &region, "register RAM");
    region.slot = 1;
    region.guest_phys_addr = EPC_BASE;
    region.memory_size = EPC_SIZE;
    region.userspace_addr = (uintptr_t)*epc;
    check_ioctl(*vm_fd, KVM_SET_USER_MEMORY_REGION, &region, "register EPC");
    cpu_fd = ioctl(*vm_fd, KVM_CREATE_VCPU, 0);
    if (cpu_fd < 0) fail("KVM_CREATE_VCPU");
    struct kvm_cpuid2 *cpuid = calloc(1, sizeof(*cpuid) + 512 * sizeof(cpuid->entries[0]));
    if (!cpuid) fail("allocate CPUID");
    cpuid->nent = 509;
    check_ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, cpuid, "get CPU capabilities");
    unsigned int found = 0;
    for (unsigned int i = 0; i < cpuid->nent; i++) {
        struct kvm_cpuid_entry2 *e = &cpuid->entries[i];
        if (e->function == 7 && e->index == 0) {
            if (!(e->ebx & 4) || (e->ecx & (1U << 30))) { errno = ENOTSUP; fail("expected SGX1 without FLC"); }
        }
        if (e->function == 0x12 && e->index == 0) found |= e->eax & 1;
    }
    if (!found || cpuid->nent > 509) { errno = ENOTSUP; fail("missing SGX1"); }
    cpuid->entries[cpuid->nent++] = (struct kvm_cpuid_entry2){.function = 0x12, .index = 2,
        .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX, .eax = EPC_BASE | 1, .ecx = EPC_SIZE | 1};
    cpuid->entries[cpuid->nent++] = (struct kvm_cpuid_entry2){.function = 0x12, .index = 3,
        .flags = KVM_CPUID_FLAG_SIGNIFCANT_INDEX};
    check_ioctl(cpu_fd, KVM_SET_CPUID2, cpuid, "set private CPU capabilities");
    free(cpuid);
    struct { struct kvm_msrs header; struct kvm_msr_entry value; } msrs = {0};
    msrs.header.nmsrs = 1;
    msrs.value.index = 0x3a; /* IA32_FEATURE_CONTROL, private vCPU only. */
    msrs.value.data = (1U << 18) | 1;
    if (ioctl(cpu_fd, KVM_SET_MSRS, &msrs) != 1) { errno = EINVAL; fail("private SGX feature control"); }
    *(uint64_t *)(ram + 0x1000) = 0x2007;
    *(uint64_t *)(ram + 0x2000) = 0x3007;
    *(uint64_t *)(ram + 0x2008) = 0x4007;
    uint64_t *pd = (uint64_t *)(ram + 0x3000);
    for (unsigned int i = 0; i < RAM_SIZE / (2ULL << 20); i++) pd[i] = i * (2ULL << 20) | 0x87;
    for (uint64_t i = 0; i < EPC_SIZE; i += PAGE) map_page(EPC_BASE + i, EPC_BASE + i, 7);
    memcpy(ram + CODE_BASE, _binary_vm_guest_bin_start,
           (size_t)(_binary_vm_guest_bin_end - _binary_vm_guest_bin_start));
    uint64_t *gdt = (uint64_t *)(ram + 0x92000);
    gdt[1] = 0x00af9b000000ffffULL;
    gdt[2] = 0x00cf93000000ffffULL;
    gdt[3] = 0x00affb000000ffffULL;
    gdt[4] = 0x00cff3000000ffffULL;
    uint64_t tss_base = 0x90000;
    gdt[5] = 0x67 | ((tss_base & 0xffffff) << 16) | (0x89ULL << 40);
    memcpy(ram + tss_base + 4, &(uint64_t){0x80000}, 8);
    memcpy(ram + tss_base + 102, &(uint16_t){104}, 2);
    for (unsigned int i = 0; i < 256; i++) {
        uint8_t *entry = ram + 0x91000 + i * 16;
        uint64_t handler = CODE_BASE + 0x300;
        memcpy(entry, &(uint16_t){handler & 0xffff}, 2);
        memcpy(entry + 2, &(uint16_t){8}, 2);
        entry[5] = 0x8e;
        memcpy(entry + 6, &(uint16_t){(handler >> 16) & 0xffff}, 2);
    }
    check_ioctl(cpu_fd, KVM_GET_SREGS, &baseline, "get initial CPU state");
    baseline.cs = segment(8, 11, 0, 1);
    baseline.ss = baseline.ds = baseline.es = segment(16, 3, 0, 0);
    baseline.fs = baseline.gs = baseline.ds;
    baseline.tr = (struct kvm_segment){.base = tss_base, .limit = 0x67,
                                     .selector = 0x28, .type = 11, .present = 1};
    baseline.gdt.base = 0x92000;
    baseline.gdt.limit = 7 * 8 - 1;
    baseline.idt.base = 0x91000;
    baseline.idt.limit = 4095;
    baseline.cr0 = 0x80000031;
    baseline.cr3 = 0x1000;
    baseline.cr4 = 0x40620;
    baseline.efer = 0xd00;
    struct kvm_xcrs xcrs = {.nr_xcrs = 1};
    xcrs.xcrs[0].value = 3;
    check_ioctl(cpu_fd, KVM_SET_XCRS, &xcrs, "set private XCR0");
    struct kvm_fpu fpu = {.fcw = 0x37f, .mxcsr = 0x1f80};
    check_ioctl(cpu_fd, KVM_SET_FPU, &fpu, "set private FPU");
    *run_size = (size_t)ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    run = mmap(NULL, *run_size, PROT_READ | PROT_WRITE, MAP_SHARED, cpu_fd, 0);
    if (run == MAP_FAILED) fail("map vCPU control");
}

int main(int argc, char **argv)
{
    if (argc != 9 || getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 ||
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) {
        fprintf(stderr, "Use run_trial.py; the runner must be unprivileged with NNP.\n");
        return 1;
    }
    setbuf(stdout, NULL);
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core)) fail("disable core dumps");
    printf("runner_uid=1000 runner_gid=1000 no_new_privs=1 windows=0 qemu=0 guest_os=0\n");
    struct sigaction sa = {.sa_handler = timeout_handler};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGALRM, &sa, NULL)) fail("deadline signal");
    alarm(30);
    int epc_fd = atoi(argv[1]);
    struct stat st;
    if (fstat(epc_fd, &st) || !S_ISCHR(st.st_mode)) { errno = EINVAL; fail("inherited EPC FD"); }
    int kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
    if (kvm_fd < 0) fail("open /dev/kvm");
    if (ioctl(kvm_fd, KVM_GET_API_VERSION, 0) != 12) { errno = ENOTSUP; fail("KVM API"); }
    int vm_fd = -1;
    void *epc = NULL;
    size_t run_size = 0;
    setup_vm(kvm_fd, epc_fd, &vm_fd, &epc, &run_size);
    transport_fd = atoi(argv[7]);
    capture_enabled = atoi(argv[8]);
#ifdef GXFP_PERSISTENT_CAPTURE
    if (capture_enabled < 0 || capture_enabled > 2) { errno = EINVAL; fail("capture option"); }
#else
    if (capture_enabled != 0 && capture_enabled != 1) { errno = EINVAL; fail("capture option"); }
#endif
    if (transport_fd >= 0) {
        if (fstat(transport_fd, &st) || !S_ISSOCK(st.st_mode)) { errno = EINVAL; fail("private transport FD"); }
        struct timeval timeout = {.tv_sec = 5};
        if (setsockopt(transport_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
                setsockopt(transport_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) fail("RPC timeout");
    }
    int sealed_fd = atoi(argv[6]);
    if (sealed_fd >= 0) {
        if (sealed_fd == epc_fd || fstat(sealed_fd, &st) || !S_ISREG(st.st_mode) ||
                st.st_size < 0x230 || st.st_size > 2044 ||
                fcntl(sealed_fd, F_GET_SEALS) != (F_SEAL_SEAL | F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK)) {
            errno = EINVAL; fail("sealed encrypted BIOS RAM FD");
        }
        encrypted_bios_length = (uint32_t)st.st_size;
        read_exact(sealed_fd, ram + SEALED_INPUT, encrypted_bios_length);
        close(sealed_fd);
    }
    struct image le = {0}, goodix = {0};
    int result = load_image(argv[2], LE_BASE, &le);
    if (!result) {
        int fd = open(argv[3], O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0) fail("open Intel production signature");
        if (fstat(fd, &st) || st.st_size != 1808) { errno = EINVAL; fail("production signature size"); }
        read_exact(fd, ram + SIGNATURE, 1808);
        close(fd);
        memset(ram + TOKEN, 0, 1024);
        unsigned int retries;
        result = initialize_enclave(le.secs, &retries);
        printf("intel_le_einit_result=%d intel_le_einit_retries=%u\n", result, retries);
    }
    if (!result) {
        result = initialize_runtime(&le);
        printf("intel_le_runtime_init_result=%d\n", result);
    }
    if (!result) result = load_image(argv[4], GOODIX_BASE, &goodix);
    if (!result) result = authorize_goodix(&le, &goodix, argv[5]);
    int goodix_einit_attempted = 0;
    if (!result) {
        goodix_einit_attempted = 1;
        unsigned int retries;
        result = initialize_enclave(goodix.secs, &retries);
        printf("goodix_einit_result=%d goodix_einit_retries=%u\n", result, retries);
        explicit_bzero(ram + TOKEN, 1024);
    }
    if (!result) {
        result = initialize_runtime(&goodix);
        printf("goodix_runtime_init_result=%d\n", result);
    }
    if (!result) {
        memset(ram + PARAMS, 0, PAGE);
        *(int32_t *)(ram + PARAMS) = -1;
        *(int32_t *)(ram + PARAMS + 4) = 7;
        result = goodix_call(goodix.first_tcs, 0x2d, PARAMS);
        printf("goodix_application_init_result=0x%x\n", *(uint32_t *)(ram + PARAMS));
        if (*(uint32_t *)(ram + PARAMS)) result = -1;
    }
    if (!result && encrypted_bios_length) {
        memset(ram + PARAMS, 0, PAGE);
        *(int32_t *)(ram + PARAMS) = -1;
        *(int32_t *)(ram + PARAMS + 4) = 7;
        result = goodix_call(goodix.first_tcs, 0x27, PARAMS);
        printf("goodix_tls_init_result=0x%x\n", *(uint32_t *)(ram + PARAMS));
        if (*(uint32_t *)(ram + PARAMS) || pmk_success_length != 48 || unseal_error) result = -1;
        if (!result && capture_enabled) result = initialize_images(&goodix);
        if (!result && transport_fd >= 0) result = sensor_handshake(&goodix);
        if (!result && capture_enabled) {
#ifdef GXFP_PERSISTENT_CAPTURE
            if (capture_enabled == 2) result = sensor_capture_session(&goodix);
            else
#endif
            result = sensor_capture(&goodix);
        }
        if (transport_fd >= 0) {
            uint32_t received = 0;
            int finish = bridge_call(5, NULL, 0, NULL, 0, &received);
            printf("tls_bridge_finish_result=%d\n", finish);
            if (finish) result = -1;
            close(transport_fd); transport_fd = -1;
        }
        int cleanup_result = goodix_call(goodix.first_tcs, 0x28, 0);
        printf("goodix_tls_exit_result=%d\n", cleanup_result);
        if (cleanup_result) result = -1;
        explicit_bzero(ram + SEALED_INPUT, 2044);
    }
    printf("filtered_log_ocalls=%llu pmk_success_length=%u unseal_error=%u\n",
           (unsigned long long)ocall_counts[14], pmk_success_length, unseal_error);
    printf("me_info_ocalls=%llu cache_miss_ocalls=%llu\n",
           (unsigned long long)ocall_counts[6], (unsigned long long)ocall_counts[7]);
    printf("tls_final_connected_callbacks=%u invalid_mac_callbacks=%u tls_state=%u\n",
           tls_connected_count, tls_invalid_mac_count, tls_last_state);
    printf("trial_result=%d goodix_einit_attempted=%d bios_read=%d tls_sensor_connected=%u\n",
           result, goodix_einit_attempted, !!encrypted_bios_length, tls_connected_count);
    alarm(0);
    close(cpu_fd); cpu_fd = -1;
    close(vm_fd);
    munmap(run, run_size); run = NULL;
    munmap(epc, EPC_SIZE);
    close(epc_fd);
    explicit_bzero(ram, RAM_SIZE);
    munmap(ram, RAM_SIZE);
    close(kvm_fd);
    printf("vm_closed=1 epc_mapping_released=1\n");
    return result ? 1 : 0;
}
