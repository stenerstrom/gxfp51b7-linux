/* SPDX-License-Identifier: GPL-2.0-only */
/* Included after the bounded probe helpers. One root-owned experiment,
 * with explicit START and automatic FINISH on close. Only one verified
 * ChicagoHS image requests with their fixed original runtime configuration
 * is available; no TLS application writes.
 */
#include "chicago_config.h"
#define STREAM_START _IO('G', 1)
#define STREAM_STATE _IOR('G', 2, int)
#define STREAM_CAPTURE _IO('G', 3)
#define STREAM_IDLE _IO('G', 4)
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
#include <linux/cred.h>
#define STREAM_ENGINE_IDENTITY _IOR('G', 5, u8[GXFP_ENGINE_IDENTITY_SIZE])
static_assert(STREAM_ENGINE_IDENTITY == 0x80104705U);
#endif
#ifdef GXFP_ORIGINAL_ENGINE_SERVICE
#include "engine_metadata.h"
#define STREAM_ENGINE_METADATA _IOR('G', 6, u8[GXFP_ENGINE_METADATA_SIZE])
static_assert(STREAM_ENGINE_METADATA == 0x80184706U);
#endif
#define STREAM_RX_LIMIT 0x7000
#define STREAM_TX_LIMIT 0x1000

struct tls_stream_device {
	struct miscdevice misc;
	struct mutex lock;
	struct device *dev;
	void __iomem *mmio;
	acpi_handle handle;
	struct gpio_desc *irq, *ack;
	struct mailbox_dma dma;
	u8 *rx, *stable, *previous, *fifo, *tx;
	unsigned int fifo_length, previous_length;
	unsigned int captures;
	int initial, last_interrupts;
	int last_ack_command, last_ack_status;
	bool opened, loaded, started, negotiation_done, capture_requested, discarding;
	bool config_reply_received, configured;
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	struct gxfp_engine_identity engine_identity;
#endif
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
	struct chicago_factory_calibration factory;
	unsigned short saved_registers[CHICAGO_FACTORY_REGISTERS];
	bool factory_snapshot_ready, factory_changed;
#endif
};
static struct tls_stream_device *stream;

static int stream_command(struct tls_stream_device *s, const u8 *p, unsigned int n)
{
	return exchange(s->mmio, s->handle, s->irq, s->ack, p, n);
}

/* Use the already-proven combination of new IRQ and changed complete frame.
 * EC can update the mailbox within one IRQ. Copy before acknowledging; no
 * bytes are logged. Give the EC the same 1 ms settling delay as exchange().
 */
static int stream_receive(struct tls_stream_device *s, unsigned int timeout_ms)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(timeout_ms);
	unsigned int n;
	int interrupts, ret, level;
	bool same_frame;
	do {
		rearm_observer(s->irq);
		interrupts = atomic_read(&observer->interrupts);
		level = gpiod_get_raw_value_cansleep(s->irq);
		if (level < 0)
			return level;
		usleep_range(1000, 2000);
		memcpy_fromio(s->rx, s->mmio + 0x1000, STREAM_RX_LIMIT);
		n = frame_length(s->rx, STREAM_RX_LIMIT);
		if (!n || (!frame_valid(s->rx, n) && !frame_tls_record(s->rx, n))) {
			/* Wait for a complete frame; never parse a partial header. */
			usleep_range(1000, 2000);
			continue;
		}
		same_frame = n == s->previous_length && !memcmp(s->rx, s->previous, n);
		if (interrupts == s->last_interrupts && same_frame)
			continue;
		if ((s->rx[0] & 0xf0) == 0xb0) {
			/* TLS has no outer payload checksum. A changed header is
			 * insufficient evidence that EC DMA has finished the body.
			 * A new IRQ or changed complete frame starts the check.
			 * The GPIO pulse may already have ended when we sample it;
			 * require an unchanged second copy before releasing DMA. */
			dma_rmb();
			usleep_range(5000, 6000);
			memcpy_fromio(s->stable, s->mmio + 0x1000, n);
			if (memcmp(s->rx, s->stable, n)) {
				LOG("stream_tls_snapshot_changed_before_ack=1 bytes=%u\n", n);
				continue;
			}
			LOG("stream_tls_snapshot_stable=1 bytes=%u irq_level=%d new_irq=%u\n",
			    n, level, interrupts != s->last_interrupts);
			memzero_explicit(s->stable, STREAM_RX_LIMIT);
			/* A new IRQ may announce the same completed TLS frame again.
			 * A repeated TLS ciphertext record cannot advance the TLS
			 * sequence number; delivering it twice produces INVALID_MAC.
			 * Still acknowledge the transport repeat. Control ACKs with
			 * identical bytes remain valid when a new IRQ arrives.
			 */
			if (same_frame) {
				s->last_interrupts = interrupts;
				LOG("stream_identical_tls_repeat_discarded=1 bytes=%u\n", n);
				acknowledge(s->ack);
				usleep_range(1000, 2000);
				rearm_observer(s->irq);
				memzero_explicit(s->rx, STREAM_RX_LIMIT);
				continue;
			}
		}
		s->last_interrupts = interrupts;
		memcpy(s->previous, s->rx, n);
		s->previous_length = n;
		ret = 1;
		if ((s->rx[0] & 0xf0) == 0xb0 && !s->discarding) {
			if (n - 4 > STREAM_RX_LIMIT - s->fifo_length)
				ret = -ENOSPC;
			else {
				memcpy(s->fifo + s->fifo_length, s->rx + 4, n - 4);
				s->fifo_length += n - 4;
				LOG("stream_rx_tls_bytes=%u record_type=%u\n", n - 4, s->rx[4]);
			}
		} else if ((s->rx[0] & 0xf0) == 0xa0) {
			LOG("stream_rx_control_command=0x%02x bytes=%u\n", s->rx[4], n);
			if (s->rx[4] == 0xb0 && n == 10) {
				s->last_ack_command = s->rx[7];
				s->last_ack_status = s->rx[8];
				LOG("stream_control_ack_command=0x%02x status=0x%02x\n",
				    s->last_ack_command, s->last_ack_status);
			} else if (s->rx[4] == 0x90) {
				/* data_from_device 0x180051dc5 signals the config
				 * completion event for this validated response. */
				s->config_reply_received = true;
				LOG("stream_config_response_received=1 payload_bytes=%u\n", n - 8);
			}
		}
		acknowledge(s->ack);
		/* Allow EC to release its level before enabling the held IRQ. */
		usleep_range(1000, 2000);
		rearm_observer(s->irq);
		memzero_explicit(s->rx, STREAM_RX_LIMIT);
		return ret;
	} while (time_before(jiffies, deadline));
	return -ETIMEDOUT;
}

static int stream_send_control(struct tls_stream_device *s, const u8 *frame,
			       unsigned int length)
{
	union acpi_object *obj;
	if (!frame_valid(frame, length) || length > STREAM_TX_LIMIT)
		return -EINVAL;
	memcpy_toio(s->mmio, frame, length);
	wmb();
	obj = acpi_evaluate_dsm(s->handle, &goodix_guid, 0, 2, NULL);
	if (!obj) return -EIO;
	ACPI_FREE(obj);
	usleep_range(1000, 2000);
	return 0;
}

static int stream_control_wait(struct tls_stream_device *s, const u8 *frame,
			       unsigned int length, bool config_response)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(2000);
	int ret;
	s->last_ack_command = -1;
	s->last_ack_status = -1;
	s->config_reply_received = false;
	ret = stream_send_control(s, frame, length);
	while (!ret && time_before(jiffies, deadline)) {
		if (s->last_ack_command == frame[4] &&
		    (!config_response || s->config_reply_received)) break;
		ret = stream_receive(s, 50);
		if (ret == -ETIMEDOUT || ret > 0) ret = 0;
	}
	if (!ret && (s->last_ack_command != frame[4] ||
	    (config_response && !s->config_reply_received))) ret = -ETIMEDOUT;
	LOG("stream_control_wait_command=0x%02x error=%d ack_status=%d config_response=%u\n",
	    frame[4], ret, s->last_ack_status, s->config_reply_received);
	return ret;
}

static int stream_capture_locked(struct tls_stream_device *s)
{
	/* ChicagoHUSetMode(2), original gfspi 0x18002d3f1..0x18002d4a0:
	 * command category 2 / subcommand 0, exactly {1, 0} and checksum.
	 * Asynchronous reception must use the full-size stream, not exchange's
	 * 512-byte diagnostic snapshot, because the answer can be an image.
	 */
	static const u8 image[] = { 0xa0, 6, 0, 0xa6, 0x20, 3, 0, 1, 0, 0x86 };
	static const u8 idle[] = { 0xa0, 6, 0, 0xa6, 0x70, 3, 0, 0x14, 0, 0x23 };
	u8 config[264];
	unsigned int config_length;
	int ret;
	if (!s->started || !s->negotiation_done) return -ENOTCONN;
	if (s->capture_requested) return -EBUSY;
	if (s->fifo_length) return -EBUSY;
	if (s->captures >= capture_limit) return -EDQUOT;
	s->last_interrupts = atomic_read(&observer->interrupts);
	memcpy_fromio(s->previous, s->mmio + 0x1000, STREAM_RX_LIMIT);
	s->previous_length = frame_length(s->previous, STREAM_RX_LIMIT);
	s->capture_requested = true; /* Always attempt idle, even on a send error. */
	s->captures++;
	capture_quiet = capture_limit > 64 && s->captures > 2;
	/* gf_set_config first enters idle, sends the type-specific 256-byte
	 * runtime payload with command 0x90 and waits for its response, then
	 * ChicagoHUSetMode(2) requests the image. No firmware/key write. */
	if (!s->configured || capture_limit <= 64) {
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
		unsigned int i, matched = 0;
		unsigned short observed = 0;
		if (!s->factory_snapshot_ready) return -EINVAL;
		config_length = chicago_factory_config_frame(config, sizeof(config), &s->factory);
#else
		config_length = chicago_config_frame(config, sizeof(config));
#endif
		if (!config_length || !frame_valid(config, config_length)) {
			memzero_explicit(config, sizeof(config));
			return -EINVAL;
		}
		ret = stream_control_wait(s, idle, sizeof(idle), false);
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
		if (!ret) {
			s->factory_changed = true; /* Restore also after a partial command. */
			ret = chicago_factory_set_dac(s->mmio, s->handle, s->irq, s->ack, s->factory.otp.dac);
		}
#endif
		if (!ret) ret = stream_control_wait(s, config, config_length, true);
		memzero_explicit(config, sizeof(config));
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
		for (i = 0; !ret && i < 4; i++) {
			ret = chicago_factory_get_register(s->mmio, s->handle, s->irq, s->ack, i, &observed);
			if (!ret && observed == s->factory.otp.dac[i]) matched++;
		}
		memzero_explicit(&observed, sizeof(observed));
		if (!ret && matched != 4) ret = -EIO;
		LOG("factory_apply_error=%d factory_dac_readback_matches=%u factory_config_crc_valid=1\n", ret, matched);
#else
		LOG("stream_original_default_config_error=%d sensor_type=12 payload_bytes=256 otp_patches=0\n", ret);
#endif
		if (ret) return ret;
		s->configured = true;
	}
	s->last_ack_command = -1;
	s->last_ack_status = -1;
	ret = stream_send_control(s, image, sizeof(image));
	LOG("stream_image_request_error=%d command=0x20 payload_bytes=2\n", ret);
	return ret;
}

static int stream_capture_idle(struct tls_stream_device *s)
{
	/* ChicagoHUSetMode(7), original 0x18002da13..0x18002da8f:
	 * category 7 / subcommand 0, exactly {0x14, 0}. No reset or D2.
	 */
	static const u8 idle[] = { 0xa0, 6, 0, 0xa6, 0x70, 3, 0, 0x14, 0, 0x23 };
	unsigned long deadline = jiffies + msecs_to_jiffies(1000);
	int ret;
	if (!s->capture_requested) return 0;
	s->discarding = true;
	s->last_ack_command = -1;
	ret = stream_send_control(s, idle, sizeof(idle));
	while (!ret && time_before(jiffies, deadline) && s->last_ack_command != 0x70) {
		int received = stream_receive(s, 50);
		if (received < 0 && received != -ETIMEDOUT) ret = received;
	}
	if (!ret && s->last_ack_command != 0x70) ret = -ETIMEDOUT;
	LOG("stream_capture_idle_error=%d ack_status=%d\n", ret, s->last_ack_status);
	s->capture_requested = false;
	s->discarding = false;
	return ret;
}

static int stream_start_locked(struct tls_stream_device *s)
{
	static const u8 loaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 1, 0, 0x10 };
	static const u8 version[] = { 0xa0, 6, 0, 0xa6, 0xa8, 3, 0, 0x70, 0xdc, 0xb3 };
	static const u8 chip[] = { 0xa0, 9, 0, 0xa9, 0x82, 6, 0, 0, 0, 0, 4, 0, 0x1e };
	static const u8 state[] = { 0xa0, 5, 0, 0xa5, 0xae, 2, 0, 0x55, 0xa5 };
	static const u8 start[] = { 0xa0, 6, 0, 0xa6, 0xd0, 3, 0, 0, 0, 0xd7 };
	union acpi_object *obj;
	int ret;
	if (!s->dma.mapped) return -ENODEV;
	if (s->started || s->loaded)
		return -EBUSY;
	s->loaded = true; /* Cleanup even when the first exchange fails. */
	ret = stream_command(s, loaded, sizeof(loaded));
	if (!ret) ret = stream_command(s, version, sizeof(version));
	if (!ret) ret = stream_command(s, chip, sizeof(chip));
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
	if (!ret && !factory_chip_verified) ret = -ENODEV;
	if (!ret) ret = chicago_factory_read_calibration(s->mmio, s->handle, s->irq, s->ack, &s->factory
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
							, &s->engine_identity
#endif
							);
	if (!ret) {
		unsigned int i, matches = 0;
		for (i = 0; !ret && i < CHICAGO_FACTORY_REGISTERS; i++) {
			ret = chicago_factory_get_register(s->mmio, s->handle, s->irq, s->ack,
							  i, &s->saved_registers[i]);
			if (!ret && i < 4 && s->saved_registers[i] == s->factory.otp.dac[i]) matches++;
		}
		if (!ret) s->factory_snapshot_ready = true;
		LOG("factory_snapshot_error=%d factory_snapshot_ready=%u factory_prior_dac_matches=%u\n",
		    ret, s->factory_snapshot_ready, matches);
	}
#endif
	last_mcu_tls_connected = -1;
	if (!ret) ret = stream_command(s, state, sizeof(state));
	if (!ret && last_mcu_tls_connected != 0)
		LOG("stream_previous_sensor_tls_flag=%d restarting_original_d0=1\n", last_mcu_tls_connected);
	if (ret) return ret;
	s->last_interrupts = atomic_read(&observer->interrupts);
	memcpy_fromio(s->previous, s->mmio + 0x1000, STREAM_RX_LIMIT);
	s->previous_length = frame_length(s->previous, STREAM_RX_LIMIT);
	s->started = true;
	memcpy_toio(s->mmio, start, sizeof(start));
	wmb();
	obj = acpi_evaluate_dsm(s->handle, &goodix_guid, 0, 2, NULL);
	if (!obj) return -EIO;
	ACPI_FREE(obj);
	ret = stream_receive(s, 2000);
	LOG("stream_start_error=%d buffered_tls_bytes=%u\n", ret < 0 ? ret : 0, s->fifo_length);
	return ret < 0 ? ret : 0;
}

static void stream_finish_locked(struct tls_stream_device *s)
{
	static const u8 finish[] = { 0xa0, 6, 0, 0xa6, 0xd4, 3, 0, 0, 0, 0xd3 };
	static const u8 state[] = { 0xa0, 5, 0, 0xa5, 0xae, 2, 0, 0x55, 0xa5 };
	static const u8 unloaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 0, 0, 0x11 };
	int ret;
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	gxfp_engine_identity_clear(&s->engine_identity);
#endif
	capture_quiet = false;
	LOG("stream_total_image_requests=%u\n", s->captures);
	stream_capture_idle(s);
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
	if (s->factory_changed) {
		static const u8 idle[] = { 0xa0, 6, 0, 0xa6, 0x70, 3, 0, 0x14, 0, 0x23 };
		u8 config[264];
		unsigned short observed = 0;
		unsigned int i, bytes, matches = 0;
		int restore_error = 0, operation;
		operation = chicago_factory_transfer(s->mmio, s->handle, s->irq, s->ack,
						    idle, sizeof(idle), -1, NULL);
		if (operation) restore_error = operation;
		bytes = chicago_config_frame(config, sizeof(config));
		operation = chicago_factory_transfer(s->mmio, s->handle, s->irq, s->ack,
						    config, bytes, 0, NULL);
		if (operation) restore_error = operation;
		memzero_explicit(config, sizeof(config));
		operation = chicago_factory_set_dac(s->mmio, s->handle, s->irq, s->ack, s->saved_registers);
		if (operation) restore_error = operation;
		/* Restore every measured analogue/timing register and check it. */
		for (i = 0; i < CHICAGO_FACTORY_REGISTERS; i++) {
			operation = chicago_factory_write_register(s->mmio, s->handle, s->irq, s->ack,
								     i, s->saved_registers[i]);
			if (operation) restore_error = operation;
		}
		for (i = 0; i < CHICAGO_FACTORY_REGISTERS; i++) {
			operation = chicago_factory_get_register(s->mmio, s->handle, s->irq, s->ack, i, &observed);
			if (!operation && observed == s->saved_registers[i]) matches++;
			else restore_error = operation ? operation : -EIO;
		}
		memzero_explicit(&observed, sizeof(observed));
		LOG("factory_restore_error=%d factory_restored_registers=%u\n", restore_error, matches);
		s->factory_changed = false;
	}
	memzero_explicit(&s->factory, sizeof(s->factory));
	memzero_explicit(s->saved_registers, sizeof(s->saved_registers));
	s->factory_snapshot_ready = false;
#endif
	if (s->started) {
		if (!s->negotiation_done) {
			ret = stream_command(s, finish, sizeof(finish));
			LOG("stream_negotiation_finish_error=%d\n", ret);
		}
		last_mcu_tls_connected = -1;
		ret = stream_command(s, state, sizeof(state));
		LOG("stream_final_state_error=%d tls_connected=%d\n", ret, last_mcu_tls_connected);
		s->started = false;
	}
	if (s->loaded) {
		ret = stream_command(s, unloaded, sizeof(unloaded));
		LOG("stream_unloaded_error=%d\n", ret);
		s->loaded = false;
		last_mcu_tls_connected = -1;
		ret = stream_command(s, state, sizeof(state));
		LOG("stream_after_unload_state_error=%d tls_connected=%d\n", ret, last_mcu_tls_connected);
	}
	s->fifo_length = 0;
	memzero_explicit(s->fifo, STREAM_RX_LIMIT);
	memzero_explicit(s->rx, STREAM_RX_LIMIT);
	memzero_explicit(s->stable, STREAM_RX_LIMIT);
	memzero_explicit(s->previous, STREAM_RX_LIMIT);
	memzero_explicit(s->tx, STREAM_TX_LIMIT);
	gpiod_set_raw_value_cansleep(s->ack, s->initial);
}

static int tls_device_open(struct inode *inode, struct file *file)
{
	struct tls_stream_device *s = stream;
	int ret = 0;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	if (!s) return -ENODEV;
	mutex_lock(&s->lock);
	if (s->opened) ret = -EBUSY;
	else {
		s->opened = true;
		file->private_data = s;
		ret = stream_open(inode, file);
		if (ret) s->opened = false;
	}
	mutex_unlock(&s->lock);
	return ret;
}

static int stream_release(struct inode *inode, struct file *file)
{
	struct tls_stream_device *s = file->private_data;
	int ret;
	mutex_lock(&s->lock);
	stream_finish_locked(s);
	ret = remove_mailbox_dma(&s->dma);
	LOG("stream_release_dma_error=%d\n", ret);
	LOG("stream_session_closed=1 ack_restored=%d observed_interrupts_total=%d\n",
	    gpiod_get_raw_value_cansleep(s->ack), atomic_read(&observer->interrupts));
	s->opened = false;
	mutex_unlock(&s->lock);
	return 0;
}

static ssize_t stream_read(struct file *file, char __user *buffer, size_t n, loff_t *offset)
{
	struct tls_stream_device *s = file->private_data;
	unsigned long deadline = jiffies + msecs_to_jiffies(250);
	ssize_t ret = -ETIMEDOUT;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	if (!n) return 0;
	mutex_lock(&s->lock);
	if (!s->started) { ret = -ENOTCONN; goto done; }
	while (!s->fifo_length && time_before(jiffies, deadline)) {
		ret = stream_receive(s, 50);
		if (ret < 0 && ret != -ETIMEDOUT) goto done;
	}
	if (!s->fifo_length) { ret = -ETIMEDOUT; goto done; }
	n = min_t(size_t, n, s->fifo_length);
	if (copy_to_user(buffer, s->fifo, n)) { ret = -EFAULT; goto done; }
	s->fifo_length -= n;
	memmove(s->fifo, s->fifo + n, s->fifo_length);
	memzero_explicit(s->fifo + s->fifo_length, n);
	ret = n;
done:
	/* A bounded empty TLS poll is normal, not a session failure. */
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	if (ret < 0 && ret != -ETIMEDOUT) gxfp_engine_identity_clear(&s->engine_identity);
#endif
	mutex_unlock(&s->lock);
	return ret;
}

static ssize_t stream_write(struct file *file, const char __user *buffer, size_t n, loff_t *offset)
{
	struct tls_stream_device *s = file->private_data;
	union acpi_object *obj;
	ssize_t ret;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	if (n < 5 || n > STREAM_TX_LIMIT - 4) return -EMSGSIZE;
	mutex_lock(&s->lock);
	if (!s->started) { ret = -ENOTCONN; goto done; }
	if (copy_from_user(s->tx + 4, buffer, n)) { ret = -EFAULT; goto done; }
	s->tx[0] = 0xb0; s->tx[1] = n; s->tx[2] = n >> 8;
	s->tx[3] = (u8)(s->tx[0] + s->tx[1] + s->tx[2]);
	/* The first experiment sends only handshake, change-cipher and alert
	 * records. Reject application records and incomplete/concatenated TLS.
	 */
	if (!frame_tls_record(s->tx, n + 4) || s->tx[4] == 23) {
		ret = -EINVAL; goto done;
	}
	/* Drain a pending reply before replacing the independent TX area. */
	if (atomic_read(&observer->interrupts) != s->last_interrupts) {
		ret = stream_receive(s, 50);
		/* An acknowledged duplicate can consume the IRQ without adding
		 * a new TLS record. Empty after that bounded drain is normal.
		 */
		if (ret < 0 && ret != -ETIMEDOUT) goto done;
	}
	memcpy_toio(s->mmio, s->tx, n + 4);
	wmb();
	obj = acpi_evaluate_dsm(s->handle, &goodix_guid, 0, 2, NULL);
	if (!obj) { ret = -EIO; goto done; }
	ACPI_FREE(obj);
	LOG("stream_tx_tls_bytes=%zu record_type=%u\n", n, s->tx[4]);
	/* Original SendTLSPackage calls PeripheralWriteWrapper and Sleep(1),
	 * without requiring a command ACK. Responses arrive asynchronously.
	 */
	usleep_range(1000, 2000);
	ret = n;
done:
	memzero_explicit(s->tx, STREAM_TX_LIMIT);
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	if (ret < 0) gxfp_engine_identity_clear(&s->engine_identity);
#endif
	mutex_unlock(&s->lock);
	return ret;
}

static long stream_ioctl(struct file *file, unsigned int command, unsigned long argument)
{
	static const u8 state[] = { 0xa0, 5, 0, 0xa5, 0xae, 2, 0, 0x55, 0xa5 };
	static const u8 finish[] = { 0xa0, 6, 0, 0xa6, 0xd4, 3, 0, 0, 0, 0xd3 };
	struct tls_stream_device *s = file->private_data;
	int ret, value, attempt;
	if (!capable(CAP_SYS_ADMIN)) return -EPERM;
	mutex_lock(&s->lock);
	if (command == STREAM_START) ret = stream_start_locked(s);
#ifdef GXFP_ORIGINAL_ENGINE_SERVICE
	else if (command == STREAM_ENGINE_METADATA) {
		u8 metadata[GXFP_ENGINE_METADATA_SIZE];
		if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)) ret = -EPERM;
		else if (!gxfp_engine_metadata_encode(metadata, &s->engine_identity,
				&s->factory, s->started, s->negotiation_done)) ret = -ENOTCONN;
		else if (copy_to_user((void __user *)argument, metadata, sizeof(metadata))) ret = -EFAULT;
		else ret = 0;
		memzero_explicit(metadata, sizeof(metadata));
	}
#endif
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	else if (command == STREAM_ENGINE_IDENTITY) {
		if (!uid_eq(current_euid(), GLOBAL_ROOT_UID)) ret = -EPERM;
		else if (!gxfp_engine_identity_available(&s->engine_identity,
						       s->started, s->negotiation_done)) ret = -ENOTCONN;
		else if (copy_to_user((void __user *)argument, s->engine_identity.bytes,
				      sizeof(s->engine_identity.bytes))) ret = -EFAULT;
		else ret = 0;
	}
#endif
	else if (command == STREAM_CAPTURE) ret = stream_capture_locked(s);
	else if (command == STREAM_IDLE) {
		if (s->fifo_length) ret = -EBUSY;
		else ret = stream_capture_idle(s);
	}
	else if (command == STREAM_STATE && s->started) {
		/* Original success path 0x180029f40 sends D4, then tries MCU
		 * status three times with Sleep(10). D4 ends negotiation; it is
		 * not evidence of TLS disconnection (v2 proved flag 1 afterward).
		 */
		ret = 0;
		if (!s->negotiation_done) {
			ret = stream_command(s, finish, sizeof(finish));
			LOG("stream_negotiation_finish_error=%d\n", ret);
			if (!ret) s->negotiation_done = true;
		}
		for (attempt = 0; !ret && attempt < 3; attempt++) {
			msleep(10);
			last_mcu_tls_connected = -1;
			ret = stream_command(s, state, sizeof(state));
			if (last_mcu_tls_connected == 1) break;
		}
		value = last_mcu_tls_connected;
		if (!ret && copy_to_user((void __user *)argument, &value, sizeof(value))) ret = -EFAULT;
	} else ret = -EINVAL;
#ifdef GXFP_ORIGINAL_ENGINE_IDENTITY
	if (ret < 0) gxfp_engine_identity_clear(&s->engine_identity);
#endif
	mutex_unlock(&s->lock);
	return ret;
}

static const struct file_operations stream_fops = {
	.owner = THIS_MODULE, .open = tls_device_open, .release = stream_release,
	.read = stream_read, .write = stream_write, .unlocked_ioctl = stream_ioctl,
	.llseek = NULL,
};

static int stream_register(struct device *dev, void __iomem *mmio, acpi_handle handle,
			   struct gpio_desc *irq, struct gpio_desc *ack, int initial,
			   struct mailbox_dma *dma)
{
	struct tls_stream_device *s;
	int ret;
	if (stream) return -EBUSY;
	s = devm_kzalloc(dev, sizeof(*s), GFP_KERNEL);
	if (!s) return -ENOMEM;
	s->rx = devm_kzalloc(dev, STREAM_RX_LIMIT, GFP_KERNEL);
	s->stable = devm_kzalloc(dev, STREAM_RX_LIMIT, GFP_KERNEL);
	s->previous = devm_kzalloc(dev, STREAM_RX_LIMIT, GFP_KERNEL);
	s->fifo = devm_kzalloc(dev, STREAM_RX_LIMIT, GFP_KERNEL);
	s->tx = devm_kzalloc(dev, STREAM_TX_LIMIT, GFP_KERNEL);
	if (!s->rx || !s->stable || !s->previous || !s->fifo || !s->tx) return -ENOMEM;
	mutex_init(&s->lock);
	s->dev = dev; s->mmio = mmio; s->handle = handle;
	s->irq = irq; s->ack = ack; s->initial = initial; s->dma = *dma;
	s->misc.minor = MISC_DYNAMIC_MINOR;
	s->misc.name = "gxfp51b7_tls"; s->misc.fops = &stream_fops;
	s->misc.mode = 0600; s->misc.parent = dev;
	stream = s;
	ret = misc_register(&s->misc);
	if (ret) stream = NULL;
	return ret;
}

static void stream_remove(struct platform_device *pdev)
{
	struct tls_stream_device *s = stream;
	int ret;
	if (!s || s->dev != &pdev->dev) return;
	misc_deregister(&s->misc);
	mutex_lock(&s->lock);
	stream_finish_locked(s);
	ret = remove_mailbox_dma(&s->dma);
	LOG("stream_removed=1 dma_cleanup_error=%d ack_restored=%d observed_interrupts_total=%d\n",
	    ret, gpiod_get_raw_value_cansleep(s->ack), atomic_read(&observer->interrupts));
	mutex_unlock(&s->lock);
	stream = NULL;
}
