/* Synthetic outside-stack bounds checks; never opens KVM or SGX devices. */
#define main unused_wbdi_trial_main
#include "kvm_runner.c"
#undef main
#include <assert.h>

int main(void)
{
    const uint64_t bottom = KVM_OUTSIDE_STACK_BOTTOM;
    const uint64_t top = KVM_OUTSIDE_STACK_TOP;
    const size_t size = (size_t)(top - bottom);
    const size_t calibration_payload = 0x224c0;
    const size_t calibration_record = 32;
    ram = calloc(1, RAM_SIZE);
    assert(ram);
    assert(outside_pointer(bottom, size) == ram + bottom);
    assert(outside_pointer(top, 0) == ram + top);
    assert(!outside_pointer(bottom - 1, 1));
    assert(!outside_pointer(top, 1));
    assert(!outside_pointer(top + 1, 0));
    assert(!outside_pointer(UINT64_MAX, 1));
    assert(!outside_pointer(bottom, SIZE_MAX));
    assert(!outside_pointer(bottom, size + 1));
    assert(outside_resume_valid(bottom, 0));
    assert(outside_resume_valid(top, bottom));
    assert(!outside_resume_valid(bottom - 1, 0));
    assert(!outside_resume_valid(top + 1, 0));
    assert(!outside_resume_valid(top, bottom - 1));
    assert(!outside_resume_valid(top, top + 1));
    assert(!outside_resume_valid(0, 0));

    uint64_t payload = top - calibration_payload;
    uint64_t record = payload - calibration_record;
    if (size == 0x10000) {
        assert(bottom == 0x70000 && top == 0x80000);
        assert(!outside_pointer(payload, calibration_payload));
        assert(!outside_pointer(record, calibration_record));
        assert(!outside_resume_valid(record, 0));
    } else {
        assert(bottom == 0x180000 && top == 0x280000 && size == 0x100000);
        assert(outside_pointer(payload, calibration_payload) == ram + payload);
        assert(outside_pointer(record, calibration_record) == ram + record);
        assert(outside_resume_valid(record, top));
        memset(ram + CONTROL, 0x55, PAGE);
        memset(ram + CODE_BASE, 0x66, PAGE);
        memset(ram + SOURCE, 0x77, PAGE);
        memset(outside_pointer(payload, calibration_payload), 0xaa, calibration_payload);
        memset(outside_pointer(record, calibration_record), 0xbb, calibration_record);
        for (unsigned int i = 0; i < PAGE; i++) {
            assert(ram[CONTROL + i] == 0x55);
            assert(ram[CODE_BASE + i] == 0x66);
            assert(ram[SOURCE + i] == 0x77);
        }
    }

    const char message[] = "count 7";
    uint64_t text = top - sizeof(message);
    memcpy(ram + text, message, sizeof(message));
    assert(filtered_scalar(text, "count ", 10) == 7);
    ram[top - 1] = 'x'; /* No terminator before the configured boundary. */
    assert(filtered_scalar(text, "count ", 10) == 0);
    assert(!outside_pointer(CONTROL, 1) && !outside_pointer(CODE_BASE, 1));
    assert(!outside_pointer(SOURCE, 1));
    explicit_bzero(ram, RAM_SIZE);
    free(ram); ram = NULL;
    printf("{\"outside_stack_checks_passed\":true,\"bottom\":%llu,\"top\":%llu,"
           "\"bytes\":%zu,\"calibration_marshal_fits\":%s,\"hardware_used\":false}\n",
           (unsigned long long)bottom, (unsigned long long)top, size,
           size > calibration_payload + calibration_record ? "true" : "false");
    return 0;
}
