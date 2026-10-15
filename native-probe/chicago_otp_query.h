/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_CHICAGO_OTP_QUERY_H
#define GXFP_CHICAGO_OTP_QUERY_H
#include "chicago_otp.h"

/* One fixed factory-calibration getter. No raw byte reaches sysfs/userspace.
 * Own gf_get_otp 0x1800578cc: category A/subcommand 3, two zero bytes.
 */
static int chicago_otp_query(void __iomem *mmio, acpi_handle handle,
			     struct gpio_desc *irq, struct gpio_desc *ack)
{
	static const u8 request[] = { 0xa0, 6, 0, 0xa6, 0xa6, 3, 0, 0, 0, 1 };
	u8 previous[512], rx[512], stable[512];
	struct chicago_otp_result result = { };
	union acpi_object *obj;
	unsigned long deadline;
	unsigned int n, frames = 0;
	int ret = -ETIMEDOUT, before_irq, interrupts;
	bool received_ack = false;
	if (!observer || !frame_valid(request, sizeof(request))) return -EINVAL;
	memcpy_fromio(previous, mmio + 0x1000, sizeof(previous));
	before_irq = atomic_read(&observer->interrupts);
	memcpy_toio(mmio, request, sizeof(request));
	wmb();
	obj = acpi_evaluate_dsm(handle, &goodix_guid, 0, 2, NULL);
	if (!obj) { ret = -EIO; goto done; }
	ACPI_FREE(obj);
	deadline = jiffies + msecs_to_jiffies(2000);
	while (time_before(jiffies, deadline) && frames < 8) {
		usleep_range(1000, 2000);
		interrupts = atomic_read(&observer->interrupts);
		memcpy_fromio(rx, mmio + 0x1000, sizeof(rx));
		if (interrupts == before_irq && !memcmp(previous, rx, sizeof(rx))) continue;
		n = frame_length(rx, sizeof(rx));
		if (!n || !frame_valid(rx, n)) continue;
		dma_rmb();
		usleep_range(1000, 2000);
		memcpy_fromio(stable, mmio + 0x1000, n);
		if (memcmp(rx, stable, n)) continue;
		before_irq = interrupts;
		memcpy(previous, rx, sizeof(previous));
		frames++;
		if (rx[4] == 0xb0 && n == 10 && rx[7] == 0xa6) received_ack = true;
		if (rx[4] == 0xa6 && n == 72 &&
		    chicago_otp_analyze(rx + 7, 64, &result)) ret = 0;
		acknowledge(ack);
		usleep_range(1000, 2000);
		rearm_observer(irq);
		if (!ret) break;
	}
done:
	LOG("otp_query_error=%d otp_ack_received=%u otp_valid_frames=%u\n",
	    ret, received_ack, frames);
	if (!ret) {
		LOG("otp_bytes=64 otp_vendor_selection=%u otp_ft_info_valid=%u otp_ft_dac_valid=%u otp_mt_info_valid=%u otp_mt_dac_valid=%u\n",
		    result.selection, !!(result.flags & CHICAGO_OTP_FT_INFO),
		    !!(result.flags & CHICAGO_OTP_FT_DAC), !!(result.flags & CHICAGO_OTP_MT_INFO),
		    !!(result.flags & CHICAGO_OTP_MT_DAC));
		LOG("otp_dac_repaired=%u otp_dac_nonzero=%u otp_dac_nonblank=%u otp_raw_bytes_logged=0 otp_registers_written=0\n",
		    !!(result.flags & CHICAGO_OTP_REPAIRED), !!(result.flags & CHICAGO_OTP_NONZERO),
		    !!(result.flags & CHICAGO_OTP_NONBLANK));
	}
	memzero_explicit(previous, sizeof(previous));
	memzero_explicit(rx, sizeof(rx));
	memzero_explicit(stable, sizeof(stable));
	memzero_explicit(&result, sizeof(result));
	return ret;
}
#endif
