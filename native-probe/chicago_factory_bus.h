/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_CHICAGO_FACTORY_BUS_H
#define GXFP_CHICAGO_FACTORY_BUS_H
#include "chicago_factory_config.h"
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
#include "engine_identity.h"
#endif

/* Private controls used only at idle, before capture or after TLS exit.
 * No wire payload, OTP identity or analogue value is logged or exported.
 * response_bytes: -1 = ACK only, 0 = bounded completion, >0 = exact getter.
 */
static int chicago_factory_transfer_once(void __iomem *mmio, acpi_handle handle,
				    struct gpio_desc *irq, struct gpio_desc *ack,
				    const u8 *request, unsigned int bytes,
				    int response_bytes, u8 *output, unsigned int timeout_ms)
{
	u8 previous[512], rx[512], stable[512];
	union acpi_object *obj;
	unsigned long deadline;
	unsigned int n, frames = 0, polls = 0, changed_polls = 0, falling_edges = 0;
	unsigned int invalid_frames = 0, unstable_frames = 0, initial_irq;
	unsigned int ready_wait_polls = 0;
	int ret = -ETIMEDOUT, before_irq, interrupts, last_level, level;
	int initial_level;
	int irq_ack_status = -1;
	bool irq_ack_used = false;
	bool submitted = false;
	bool got_ack = false, got_response = false;
	if (!observer || !request || bytes < 8 || bytes > 264 || !frame_valid(request, bytes) ||
	    response_bytes < -1 || response_bytes > 64 || (response_bytes > 0 && !output))
		return -EINVAL;
	last_level = gpiod_get_raw_value_cansleep(irq);
	if (last_level < 0) return last_level;
	initial_level = last_level;
	initial_irq = (unsigned int)atomic_read(&observer->interrupts);
	deadline = jiffies + msecs_to_jiffies(timeout_ms);
	/* ACK high does not mean the EC has already released its input level.
	 * Starting a new command while the old response still holds IRQ low can
	 * lose both the new edge and an identical ACK. Wait for a clean high
	 * level, then rearm, before taking the new transaction's baseline.
	 * This consumes the existing timeout budget; it never pulses ACK or
	 * resubmits a write to make the line appear ready.
	 */
	for (;;) {
		if (last_level == 1) {
			rearm_observer(irq);
			last_level = gpiod_get_raw_value_cansleep(irq);
			if (last_level < 0) { ret = last_level; goto done; }
			if (last_level == 1) break;
		}
		if (!time_before(jiffies, deadline)) goto done;
		usleep_range(1000, 2000);
		ready_wait_polls++;
		last_level = gpiod_get_raw_value_cansleep(irq);
		if (last_level < 0) { ret = last_level; goto done; }
	}
	memcpy_fromio(previous, mmio + 0x1000, sizeof(previous));
	before_irq = atomic_read(&observer->interrupts);
	chicago_control_snapshot_begin(&observer->control, mmio + 0x1000, request[4], previous);
	memcpy_toio(mmio, request, bytes);
	wmb();
	submitted = true;
	obj = acpi_evaluate_dsm(handle, &goodix_guid, 0, 2, NULL);
	if (!obj) { ret = -EIO; goto done; }
	ACPI_FREE(obj);
	while (time_before(jiffies, deadline) && frames < 8) {
		bool falling, changed;
		polls++;
		/* Acknowledge does not guarantee that EC has released its level
		 * within the following 1 ms. Rearm again while waiting, as the TLS
		 * receiver does. Register getters can return identical ACK bytes;
		 * a fresh falling GPIO edge is evidence even if a masked IRQ was
		 * missed. Never accept an unchanged mailbox without such evidence.
		 */
		rearm_observer(irq);
		usleep_range(1000, 2000);
		level = gpiod_get_raw_value_cansleep(irq);
		if (level < 0) { ret = level; goto done; }
		falling = last_level == 1 && level == 0;
		if (falling) falling_edges++;
		last_level = level;
		interrupts = atomic_read(&observer->interrupts);
		memcpy_fromio(rx, mmio + 0x1000, sizeof(rx));
		changed = memcmp(previous, rx, sizeof(rx)) != 0;
		if (changed) changed_polls++;
		/* DSM can return after the EC has replaced its brief ACK with the
		 * data response. The original copies in its ISR; our IRQ shadow
		 * retains only a changed, complete validated ACK for this command.
		 * The separate response keeps its existing stable/fresh checks.
		 */
		irq_ack_status = chicago_control_snapshot_status(&observer->control);
		if (irq_ack_status >= 0) {
			if (frame_length(rx, sizeof(rx)) != 10 || rx[4] != 0xb0 || rx[7] != request[4])
				irq_ack_used = true;
			if (irq_ack_status != 1) {
				ret = -EIO;
				acknowledge(ack);
				usleep_range(1000, 2000);
				rearm_observer(irq);
				goto done;
			}
			got_ack = true;
		}
		if (interrupts == before_irq && !falling && !changed) continue;
		n = frame_length(rx, sizeof(rx));
		if (!n || !frame_valid(rx, n)) { invalid_frames++; continue; }
		dma_rmb();
		usleep_range(1000, 2000);
		memcpy_fromio(stable, mmio + 0x1000, n);
		if (memcmp(rx, stable, n)) { unstable_frames++; continue; }
		before_irq = interrupts;
		memcpy(previous, rx, sizeof(previous));
		frames++;
		if (rx[4] == 0xb0 && n == 10 && rx[7] == request[4]) {
			if (rx[8] != 1) ret = -EIO;
			else got_ack = true;
		}
		else if (rx[4] == request[4] && response_bytes >= 0 &&
			 ((response_bytes > 0 && n == (unsigned int)response_bytes + 8) ||
			  (response_bytes == 0 && n >= 8 && n <= 16))) {
			if (response_bytes > 0) memcpy(output, rx + 7, response_bytes);
			got_response = true;
		}
		acknowledge(ack);
		usleep_range(1000, 2000);
		rearm_observer(irq);
		if (ret == -EIO) break;
		if (got_ack && (response_bytes == -1 || got_response)) { ret = 0; break; }
	}
done:
	chicago_control_snapshot_end(&observer->control);
	if (ready_wait_polls || !submitted)
		LOG("factory_ready_command=0x%02x ready=%u ready_wait_polls=%u submitted=%u\n",
		    request[4], submitted, ready_wait_polls, submitted);
	if (irq_ack_used)
		LOG("factory_irq_ack_command=0x%02x status=%d used=1\n", request[4], irq_ack_status);
	if (ret) {
		LOG("factory_transfer_command=0x%02x factory_transfer_error=%d factory_transfer_frames=%u factory_transfer_ack=%u factory_transfer_response=%u\n",
		    request[4], ret, frames, got_ack, got_response);
		/* Observations only: never include register indices, values or bytes.
		 * A separate short line preserves the service's 256-byte log bound.
		 */
		LOG("factory_wait_command=0x%02x error=%d polls=%u irq_delta=%u gpio_start=%d gpio_end=%d changed_polls=%u falling_edges=%u invalid_frames=%u unstable_frames=%u\n",
		    request[4], ret, polls, (unsigned int)atomic_read(&observer->interrupts) - initial_irq,
		    initial_level, last_level, changed_polls, falling_edges, invalid_frames, unstable_frames);
	}
	memzero_explicit(previous, sizeof(previous));
	memzero_explicit(rx, sizeof(rx));
	memzero_explicit(stable, sizeof(stable));
	if (ret && output && response_bytes > 0) memzero_explicit(output, response_bytes);
	return ret;
}

static int chicago_factory_transfer(void __iomem *mmio, acpi_handle handle,
				    struct gpio_desc *irq, struct gpio_desc *ack,
				    const u8 *request, unsigned int bytes,
				    int response_bytes, u8 *output)
{
	/* SpiSendDataToDevice/Lock in our original gfspi.dll has bounded
	 * same-command resubmission for a missing ACK/data response. Our narrow
	 * equivalent permits only the fixed two-byte register getter. Never
	 * repeat writes, DAC/config changes, TLS commands or an explicit NACK.
	 * Two one-second attempts retain the former total two-second budget.
	 */
	bool retry_read = request && bytes == 13 && response_bytes == 2 &&
		request[4] == 0x82 && request[5] == 6 && request[6] == 0 &&
		frame_valid(request, bytes);
	int ret = chicago_factory_transfer_once(mmio, handle, irq, ack, request, bytes,
						response_bytes, output, retry_read ? 1000 : 2000);
	if (retry_read && ret == -ETIMEDOUT) {
		/* The first attempt erased its output. ACK/response state and the
		 * freshness baseline are local to each attempt, so a partial first
		 * reply cannot be combined with the second attempt's ACK.
		 */
		ret = chicago_factory_transfer_once(mmio, handle, irq, ack, request, bytes,
						    response_bytes, output, 1000);
		LOG("factory_read_retry_command=0x82 factory_read_retry_error=%d factory_read_retry_attempts=2\n", ret);
	}
	return ret;
}

static int chicago_factory_read_calibration(void __iomem *mmio, acpi_handle handle,
					    struct gpio_desc *irq, struct gpio_desc *ack,
					    struct chicago_factory_calibration *calibration
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
					    , struct gxfp_engine_identity *identity
#endif
					    )
{
	static const u8 request[] = { 0xa0, 6, 0, 0xa6, 0xa6, 3, 0, 0, 0, 1 };
	u8 otp[64] = { };
	int ret = chicago_factory_transfer(mmio, handle, irq, ack, request, sizeof(request), 64, otp);
	if (!ret && !chicago_factory_derive(otp, sizeof(otp), calibration)) ret = -EBADMSG;
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	/* Reuse this validated reply; never submit another OTP command. */
	if (!gxfp_engine_identity_retain(identity, otp, sizeof(otp), ret == 0) && !ret)
		ret = -EBADMSG;
#endif
	LOG("factory_otp_error=%d factory_timing_valid=%u factory_vendor_selection=%u\n",
	    ret, calibration->timing_valid, calibration->otp.selection);
	memzero_explicit(otp, sizeof(otp));
	return ret;
}

static int chicago_factory_get_register(void __iomem *mmio, acpi_handle handle,
					struct gpio_desc *irq, struct gpio_desc *ack,
					unsigned int index, unsigned short *value)
{
	u8 request[13], data[2] = { };
	unsigned int bytes = chicago_factory_register_frame(request, sizeof(request), index, 0, 0);
	int ret = chicago_factory_transfer(mmio, handle, irq, ack, request, bytes, 2, data);
	/* ChipRegRead's response is big endian; the original swaps each pair. */
	if (!ret) *value = ((unsigned short)data[0] << 8) | data[1];
	memzero_explicit(request, sizeof(request));
	memzero_explicit(data, sizeof(data));
	return ret;
}

static int chicago_factory_write_register(void __iomem *mmio, acpi_handle handle,
					  struct gpio_desc *irq, struct gpio_desc *ack,
					  unsigned int index, unsigned short value)
{
	u8 request[13];
	unsigned int bytes = chicago_factory_register_frame(request, sizeof(request), index, 1, value);
	int ret = chicago_factory_transfer(mmio, handle, irq, ack, request, bytes, -1, NULL);
	memzero_explicit(request, sizeof(request));
	return ret;
}

static int chicago_factory_set_dac(void __iomem *mmio, acpi_handle handle,
				   struct gpio_desc *irq, struct gpio_desc *ack,
				   const unsigned short *dac)
{
	u8 request[16];
	unsigned int bytes = chicago_factory_dac_frame(request, sizeof(request), dac);
	int ret = chicago_factory_transfer(mmio, handle, irq, ack, request, bytes, 0, NULL);
	memzero_explicit(request, sizeof(request));
	return ret;
}
#endif
