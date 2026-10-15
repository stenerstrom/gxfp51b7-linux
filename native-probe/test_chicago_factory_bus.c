/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the real control-transfer loop with a timed synthetic mailbox.
 * No hardware, register values or image data are accessed.
 */
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <sys/resource.h>
#include "frame.h"

#define __iomem
typedef unsigned char u8;
typedef int acpi_handle;
struct gpio_desc { int unused; };
union acpi_object { int unused; };
static int goodix_guid;
static unsigned char mailbox[0x1200];
static unsigned long jiffies, due;
static int level, stage, acknowledgements;
static bool miss_irq, stale, corrupt, negative_ack, wrong_command, response_first;
static bool drop_ack_once, drop_response_once, missing_ack, second_ack_only;
static bool response_overwrites_before_poll, wrong_irq_ack, corrupt_irq_ack;
static bool tear_irq_snapshot;
static bool require_idle_before_submit;
static unsigned long previous_release_due;
static unsigned int response_size;
static unsigned int submissions;
static unsigned char command;
static char diagnostics[16384];
static size_t diagnostic_bytes;

static void capture_log(const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    int length = vsnprintf(diagnostics + diagnostic_bytes,
                           sizeof(diagnostics) - diagnostic_bytes, format, arguments);
    va_end(arguments);
    assert(length >= 0 && (size_t)length < sizeof(diagnostics) - diagnostic_bytes);
    diagnostic_bytes += (size_t)length;
}

#define atomic_read(p) (*(p))
#define msecs_to_jiffies(value) (value)
#define time_before(a, b) ((a) < (b))
#define wmb() ((void) 0)
#define dma_rmb() ((void) 0)
#define LOG(...) capture_log(__VA_ARGS__)
#define ACPI_FREE(p) ((void) (p))
static void mailbox_copy(void *destination, const void *source, size_t length);
#define memcpy_fromio(destination, source, length) mailbox_copy(destination, source, length)
#define memcpy_toio(destination, source, length) memcpy(destination, source, length)
#define memzero_explicit(destination, length) memset(destination, 0, length)

typedef int raw_spinlock_t;
#define raw_spin_lock_init(lock) (*(lock) = 0)
#define raw_spin_lock_irqsave(lock, flags) do { (void) (lock); (flags) = 0; } while (0)
#define raw_spin_unlock_irqrestore(lock, flags) do { (void) (lock); (void) (flags); } while (0)
#include "chicago_control_snapshot.h"
struct mailbox_observer {
    int interrupts;
    bool disabled;
    struct chicago_control_snapshot control;
};
static struct mailbox_observer instance, *observer = &instance;

static void packet(bool ack)
{
    unsigned char *p = mailbox + 0x1000;
    memset(p, 0, 512);
    unsigned int n = ack ? 10 : response_size + 8;
    p[0] = 0xa0; p[1] = n - 4; p[3] = 0xa0 + p[1];
    p[4] = ack ? 0xb0 : (wrong_command ? command ^ 2 : command);
    p[5] = ack ? 3 : response_size + 1;
    p[7] = ack ? (wrong_irq_ack ? command ^ 2 : command) : 0x12;
    p[8] = ack ? (negative_ack ? 0 : 1) : 0x34 + submissions - 1;
    unsigned char sum = 0;
    for (unsigned int i = 4; i < n - 1; i++) sum += p[i];
    p[n - 1] = 0xaa - sum;
    if (corrupt || (ack && corrupt_irq_ack)) p[n - 1] ^= 1;
}

static void mailbox_copy(void *destination, const void *source, size_t length)
{
    memcpy(destination, source, length);
    if (tear_irq_snapshot && length == 10) {
        tear_irq_snapshot = false;
        mailbox[0x1009] ^= 1;
    }
}

static void publish_irq(void)
{
    if (!observer->disabled && !miss_irq) {
        chicago_control_snapshot_irq(&observer->control);
        observer->interrupts++;
        observer->disabled = true;
    }
}

static void usleep_range(unsigned int minimum, unsigned int maximum)
{
    (void) maximum;
    jiffies += minimum / 1000;
    if (previous_release_due && jiffies >= previous_release_due) {
        previous_release_due = 0;
        level = 1; /* The old EC response level is finally released. */
    }
    if (due && jiffies >= due) {
        due = 0;
        packet(stage == (response_first ? 2 : 1));
        level = 0;
        publish_irq();
    }
}

static int gpiod_get_raw_value_cansleep(struct gpio_desc *gpio)
{
    (void) gpio;
    return level;
}

static void rearm_observer(struct gpio_desc *gpio)
{
    (void) gpio;
    if (level == 1) observer->disabled = false;
}

static void acknowledge(struct gpio_desc *gpio)
{
    (void) gpio;
    acknowledgements++;
    level = 1;
    if (stage == 1 && !(submissions == 1 && drop_response_once) &&
        !(submissions == 2 && second_ack_only)) {
        stage = 2;
        due = jiffies + 1;
    }
}

static union acpi_object *acpi_evaluate_dsm(acpi_handle handle, int *guid,
                                          unsigned int revision, unsigned int function, void *data)
{
    (void) handle; (void) guid; (void) revision; (void) function; (void) data;
    static union acpi_object object;
    submissions++;
    if (require_idle_before_submit && level != 1)
        return &object; /* A busy EC has no new ACK/edge to publish. */
    if (response_overwrites_before_poll) {
        /* An ACK is visible during DSM, then replaced by a valid response
         * before the waiting task resumes. The GPIO pulse has ended; only
         * one IRQ is counted. This is independent of the receive algorithm.
         */
        stage = 1;
        packet(true);
        level = 0;
        publish_irq();
        stage = 2;
        packet(false);
        level = 1;
        jiffies += 2;
        return &object;
    }
    stage = (missing_ack || (submissions == 1 && drop_ack_once)) ? 2 : 1;
    if (!stale) due = jiffies + 1;
    return &object;
}

#ifdef FACTORY_BUS_HEADER
#include FACTORY_BUS_HEADER
#else
#include "chicago_factory_bus.h"
#endif

static void reset(void)
{
    memset(mailbox, 0, sizeof(mailbox));
    memset(diagnostics, 0, sizeof(diagnostics));
    diagnostic_bytes = 0;
    jiffies = due = 0;
    acknowledgements = stage = 0;
    submissions = 0;
    level = 1;
    miss_irq = stale = corrupt = negative_ack = wrong_command = response_first = false;
    drop_ack_once = drop_response_once = missing_ack = second_ack_only = false;
    response_overwrites_before_poll = wrong_irq_ack = corrupt_irq_ack = false;
    tear_irq_snapshot = false;
    require_idle_before_submit = false;
    previous_release_due = 0;
    response_size = 2;
    observer->interrupts = 10;
    observer->disabled = true; /* EC releases its level after the last rearm attempt. */
    chicago_control_snapshot_init(&observer->control);
    command = 0x82;
    packet(true); /* Previous getter ACK is identical to the next getter ACK. */
}

static int getter(unsigned char *output)
{
    unsigned char request[13];
    unsigned int length = chicago_factory_register_frame(request, sizeof(request), 0, 0, 0);
    assert(length);
    return chicago_factory_transfer(mailbox, 0, NULL, NULL, request, length, 2, output);
}

static void test_delayed_idle_release(void)
{
    reset(); command = 0x80; packet(true); level = 0;
    require_idle_before_submit = true; previous_release_due = 8;
    assert(chicago_factory_write_register(mailbox, 0, NULL, NULL, 0, 0x1234) == 0);
    assert(submissions == 1 && observer->interrupts == 11);
    assert(strstr(diagnostics, "factory_ready_command=0x80 ready=1 ready_wait_polls=8 submitted=1\n"));
    puts("wait for previous EC level release before sending an identical-ACK write: passed");
}

int main(int argc, char **argv)
{
    (void) chicago_factory_read_calibration;
    (void) chicago_factory_get_register;
    struct rlimit no_core = {0, 0};
    setrlimit(RLIMIT_CORE, &no_core);
    if (argc == 2 && !strcmp(argv[1], "--idle-regression")) {
        test_delayed_idle_release();
        return 0;
    }
    unsigned char output[2];
    reset();
    assert(getter(output) == 0);
    assert(output[0] == 0x12 && output[1] == 0x34 && acknowledgements == 2);
    puts("identical ACK after delayed IRQ rearm: passed");

    reset(); miss_irq = true;
    assert(getter(output) == 0 && acknowledgements == 2);
    puts("fresh GPIO edge without IRQ count: passed");

    reset(); stale = true; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -ETIMEDOUT && acknowledgements == 0);
    assert(output[0] == 0 && output[1] == 0);
    puts("unchanged stale ACK cannot complete a request: passed");

    reset(); corrupt = true; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -ETIMEDOUT && acknowledgements == 0);
    assert(output[0] == 0 && output[1] == 0);
    puts("invalid checksum is rejected without acknowledgement: passed");

    reset(); negative_ack = true; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -EIO && acknowledgements == 1);
    assert(submissions == 1);
    assert(output[0] == 0 && output[1] == 0);
    puts("negative sensor ACK cannot report success: passed");

    reset(); wrong_command = true; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -ETIMEDOUT);
    assert(output[0] == 0 && output[1] == 0);
    puts("unrelated getter response is rejected: passed");

    reset(); response_first = true;
    assert(getter(output) == 0 && acknowledgements == 2);
    assert(output[0] == 0x12 && output[1] == 0x34);
    puts("response before ACK remains supported: passed");

    reset(); drop_ack_once = true;
    assert(getter(output) == 0 && submissions == 2);
    assert(output[0] == 0x12 && output[1] == 0x35);
    puts("missing first ACK retries the same read and uses its new response: passed");

    reset(); drop_response_once = true;
    assert(getter(output) == 0 && submissions == 2);
    assert(output[0] == 0x12 && output[1] == 0x35);
    puts("missing first response retries the same read: passed");

    reset(); missing_ack = true; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -ETIMEDOUT && submissions == 2);
    assert(output[0] == 0 && output[1] == 0 && jiffies <= 2000);
    puts("both missing ACKs fail closed within the original total time budget: passed");

    reset(); drop_ack_once = second_ack_only = true;
    assert(getter(output) == -ETIMEDOUT && submissions == 2);
    assert(output[0] == 0 && output[1] == 0);
    puts("ACK and response from different attempts cannot be combined: passed");

    reset(); stale = true;
    assert(chicago_factory_write_register(mailbox, 0, NULL, NULL, 0, 0x1234) == -ETIMEDOUT);
    assert(submissions == 1);
    assert(strstr(diagnostics, "factory_wait_command=0x80 error=-110 polls=2000 irq_delta=0 gpio_start=1 gpio_end=1 changed_polls=0 falling_edges=0 invalid_frames=0 unstable_frames=0\n"));
    assert(!strstr(diagnostics, "1234"));
    puts("a timed-out register write is never automatically repeated: passed");

    reset(); stale = true; level = 0; command = 0x80; packet(true);
    assert(chicago_factory_write_register(mailbox, 0, NULL, NULL, 0, 0x1234) == -ETIMEDOUT);
    assert(submissions == 0 && acknowledgements == 0);
    assert(strstr(diagnostics, "factory_wait_command=0x80 error=-110 polls=0 irq_delta=0 gpio_start=0 gpio_end=0 changed_polls=0 falling_edges=0 invalid_frames=0 unstable_frames=0\n"));
    assert(strstr(diagnostics, "factory_ready_command=0x80 ready=0 ready_wait_polls=2000 submitted=0\n"));
    puts("an old ACK held low cannot send or acknowledge a new write: passed");

    reset(); level = 0; memset(output, 0xcc, sizeof(output));
    assert(getter(output) == -ETIMEDOUT && jiffies == 2000 && submissions == 0);
    assert(acknowledgements == 0 && output[0] == 0 && output[1] == 0);
    puts("both read attempts share the original two-second budget while EC stays busy: passed");

    reset(); stale = true;
    unsigned short dac[4] = {0};
    assert(chicago_factory_set_dac(mailbox, 0, NULL, NULL, dac) == -ETIMEDOUT);
    assert(submissions == 1);
    puts("a timed-out DAC setting is never automatically repeated: passed");

    static const unsigned char otp_request[] = {0xa0, 6, 0, 0xa6, 0xa6, 3, 0, 0, 0, 1};
    unsigned char otp[64];
    reset(); command = 0xa6; response_size = 64; response_overwrites_before_poll = true;
    assert(chicago_factory_transfer(mailbox, 0, NULL, NULL,
                                   otp_request, sizeof(otp_request), 64, otp) == 0);
    assert(submissions == 1 && observer->interrupts == 11 && level == 1);
    assert(otp[0] == 0x12 && otp[1] == 0x34);
    assert(strstr(diagnostics, "factory_irq_ack_command=0xa6 status=1 used=1\n"));
    assert(!observer->control.armed && observer->control.mailbox == NULL);
    for (unsigned int i = 0; i < sizeof(observer->control.baseline); i++)
        assert(observer->control.baseline[i] == 0);
    puts("complete IRQ ACK survives mailbox replacement before the first poll: passed");

    reset(); command = 0xa6; response_size = 64;
    response_overwrites_before_poll = negative_ack = true;
    memset(otp, 0xcc, sizeof(otp));
    assert(chicago_factory_transfer(mailbox, 0, NULL, NULL,
                                   otp_request, sizeof(otp_request), 64, otp) == -EIO);
    assert(submissions == 1);
    for (unsigned int i = 0; i < sizeof(otp); i++) assert(otp[i] == 0);
    puts("early negative ACK cannot be concealed by a later valid response: passed");

    reset(); command = 0xa6; response_size = 64;
    response_overwrites_before_poll = wrong_irq_ack = true;
    assert(chicago_factory_transfer(mailbox, 0, NULL, NULL,
                                   otp_request, sizeof(otp_request), 64, otp) == -ETIMEDOUT);
    assert(submissions == 1 && !observer->control.armed);
    puts("IRQ ACK for another command cannot complete the OTP read: passed");

    reset(); command = 0xa6; response_size = 64;
    response_overwrites_before_poll = corrupt_irq_ack = true;
    assert(chicago_factory_transfer(mailbox, 0, NULL, NULL,
                                   otp_request, sizeof(otp_request), 64, otp) == -ETIMEDOUT);
    assert(submissions == 1);
    puts("corrupt early ACK cannot be replaced by success from its data response: passed");

    reset(); command = 0xa6; response_size = 64;
    response_overwrites_before_poll = tear_irq_snapshot = true;
    assert(chicago_factory_transfer(mailbox, 0, NULL, NULL,
                                   otp_request, sizeof(otp_request), 64, otp) == -ETIMEDOUT);
    assert(submissions == 1);
    puts("ACK changing between the two IRQ copies is rejected: passed");

    reset(); response_overwrites_before_poll = true;
    unsigned char register_request[13];
    unsigned int register_length = chicago_factory_register_frame(register_request, sizeof(register_request), 0, 0, 0);
    assert(chicago_factory_transfer_once(mailbox, 0, NULL, NULL,
                                        register_request, register_length, 2, output, 1000) == -ETIMEDOUT);
    puts("an unchanged old ACK is not evidence in the IRQ snapshot: passed");

    reset();
    chicago_control_snapshot_begin(&observer->control, mailbox + 0x1000, 0xa6, mailbox + 0x1000);
    command = 0xa6; packet(true);
    chicago_control_snapshot_irq(&observer->control);
    assert(chicago_control_snapshot_status(&observer->control) == 1);
    chicago_control_snapshot_end(&observer->control);
    chicago_control_snapshot_begin(&observer->control, mailbox + 0x1000, 0x82, mailbox + 0x1000);
    assert(chicago_control_snapshot_status(&observer->control) == -1);
    chicago_control_snapshot_end(&observer->control);
    chicago_control_snapshot_begin(&observer->control, mailbox + 0x1000, 0x20, mailbox + 0x1000);
    command = 0x20; packet(true);
    chicago_control_snapshot_irq(&observer->control);
    assert(chicago_control_snapshot_status(&observer->control) == -1 && !observer->control.armed);
    chicago_control_snapshot_end(&observer->control);
    packet(true); chicago_control_snapshot_irq(&observer->control);
    assert(chicago_control_snapshot_status(&observer->control) == -1);
    puts("snapshot cannot leak into another command or an unarmed TLS session: passed");

    reset();
    chicago_control_snapshot_begin(&observer->control, mailbox + 0x1000, 0xa6, mailbox + 0x1000);
    command = 0xa6; negative_ack = true; packet(true);
    chicago_control_snapshot_irq(&observer->control);
    assert(chicago_control_snapshot_status(&observer->control) == 0);
    negative_ack = false; packet(true);
    chicago_control_snapshot_irq(&observer->control);
    assert(chicago_control_snapshot_status(&observer->control) == 0);
    chicago_control_snapshot_end(&observer->control);
    puts("a later positive IRQ ACK cannot erase an earlier negative ACK: passed");
    test_delayed_idle_release();
    return 0;
}
