// SPDX-License-Identifier: GPL-2.0-only
/* Temporary, bounded transport experiment for the tested HUAWEI MACHC-WAX9.
 * No firmware update, key writes, enrollment or login changes.
 * Optional BIOS-key inspection reports only validated format metadata.
 * GPIO handshake and EC framing recovered from gfspi.dll 1.1.151.18.
 */
#include <linux/acpi.h>
#include <linux/delay.h>
#include <linux/dmi.h>
#include <linux/gpio/consumer.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/iommu.h>
#include <linux/iova.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/platform_device.h>
#include <linux/pci.h>
#include <linux/utsname.h>
#include <linux/slab.h>
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <crypto/sha2.h>
#include "frame.h"
#include "chicago_control_snapshot.h"
#include "blob.h"
#include "tls_hello.h"
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
#include "factory_startup_policy.h"
#endif

static const guid_t goodix_guid = GUID_INIT(0xcc58b68a, 0x4479, 0x4893,
	0xa8, 0xbb, 0x96, 0x12, 0x09, 0xdb, 0x59, 0xe5);
/* sysfs parameter reads have a PAGE_SIZE limit. Expose two bounded chunks
 * so longer diagnostics cannot overflow/truncate a sysfs show buffer.
 */
#define REPORT_CHUNK (PAGE_SIZE - 2)
static char report[16 * REPORT_CHUNK + 1] = "probe=not_run\n";
static int get_report_chunk(char *buffer, const struct kernel_param *kp)
{
	return scnprintf(buffer, PAGE_SIZE, "%.*s\n", (int)REPORT_CHUNK,
			 (const char *)kp->arg);
}
static const struct kernel_param_ops report_ops = { .get = get_report_chunk };
module_param_cb(report, &report_ops, report, 0444);
module_param_cb(report_tail, &report_ops, report + REPORT_CHUNK, 0444);
module_param_cb(report_more, &report_ops, report + 2 * REPORT_CHUNK, 0444);
module_param_cb(report_end, &report_ops, report + 3 * REPORT_CHUNK, 0444);
module_param_cb(report_4, &report_ops, report + 4 * REPORT_CHUNK, 0444);
module_param_cb(report_5, &report_ops, report + 5 * REPORT_CHUNK, 0444);
module_param_cb(report_6, &report_ops, report + 6 * REPORT_CHUNK, 0444);
module_param_cb(report_7, &report_ops, report + 7 * REPORT_CHUNK, 0444);
module_param_cb(report_8, &report_ops, report + 8 * REPORT_CHUNK, 0444);
module_param_cb(report_9, &report_ops, report + 9 * REPORT_CHUNK, 0444);
module_param_cb(report_10, &report_ops, report + 10 * REPORT_CHUNK, 0444);
module_param_cb(report_11, &report_ops, report + 11 * REPORT_CHUNK, 0444);
module_param_cb(report_12, &report_ops, report + 12 * REPORT_CHUNK, 0444);
module_param_cb(report_13, &report_ops, report + 13 * REPORT_CHUNK, 0444);
module_param_cb(report_14, &report_ops, report + 14 * REPORT_CHUNK, 0444);
module_param_cb(report_15, &report_ops, report + 15 * REPORT_CHUNK, 0444);
static bool run;
module_param(run, bool, 0444);
MODULE_PARM_DESC(run, "Send chip-ID and firmware queries with GPIO receive handshake");
static bool reset_first;
module_param(reset_first, bool, 0444);
MODULE_PARM_DESC(reset_first, "Precede queries with original driver's sensor reset");
static bool chip_id_only;
module_param(chip_id_only, bool, 0444);
MODULE_PARM_DESC(chip_id_only, "Send only the CHIP (0x90) query from OpenGoodixSPI #16; requires run, excludes reset_first");
static bool driver_startup;
module_param(driver_startup, bool, 0444);
MODULE_PARM_DESC(driver_startup, "Send original driver's loaded notification before read-only queries, then its unloaded notification; excludes other test modes");
static bool mcu_state;
module_param(mcu_state, bool, 0444);
MODULE_PARM_DESC(mcu_state, "Add original driver's read-only GetMcuState query; requires driver_startup");
static bool pmk_hash_metadata;
module_param(pmk_hash_metadata, bool, 0444);
MODULE_PARM_DESC(pmk_hash_metadata, "Read PMK hash using original operation 2; log metadata and known-candidate comparisons only; requires driver_startup");
static bool tls_hello_metadata;
module_param(tls_hello_metadata, bool, 0444);
MODULE_PARM_DESC(tls_hello_metadata, "Request only TLS ClientHello metadata using original D0, finish with original D4, verify MCU TLS disconnected; excludes PMK query");
static int last_mcu_tls_connected = -1;
static bool scan_mailbox_candidates;
module_param(scan_mailbox_candidates, bool, 0444);
MODULE_PARM_DESC(scan_mailbox_candidates, "Compare bounded mailbox windows with the PMK digest during ClientHello; log counts only, requires TLS metadata mode");
static u8 pmk_digest[SHA256_DIGEST_SIZE];
static bool pmk_digest_valid;
static bool observe_mailbox;
module_param(observe_mailbox, bool, 0444);
MODULE_PARM_DESC(observe_mailbox, "Register the declared interrupt and compare all 32 KiB of mailbox after each query; log only change counts");
static bool key_metadata;
module_param(key_metadata, bool, 0444);
MODULE_PARM_DESC(key_metadata, "Read BIOS key container format metadata only, erase the temporary copy; excludes sensor queries");
static bool wake_first;
module_param(wake_first, bool, 0444);
MODULE_PARM_DESC(wake_first, "Call the EC F1 notification from BIOS DSM3 directly before the startup diagnostic, bypassing its absent H_EC guard; requires driver_startup");
static bool ec_f2_only;
module_param(ec_f2_only, bool, 0444);
MODULE_PARM_DESC(ec_f2_only, "Invoke only the EC F2 counterpart from BIOS DSM4 and measure the IRQ level; no sensor commands or mailbox writes");
static bool map_mailbox;
module_param(map_mailbox, bool, 0444);
MODULE_PARM_DESC(map_mailbox, "Temporarily identity-map only the reserved 32 KiB mailbox in EC's existing DMA domain; requires run and verified running-kernel BTF");
static bool iova_layout_verified;
module_param(iova_layout_verified, bool, 0444);
static bool tls_stream;
module_param(tls_stream, bool, 0444);
MODULE_PARM_DESC(tls_stream, "Root-only, single-session TLS handshake stream; requires mapped startup and IRQ observer");
static unsigned int capture_limit = 1;
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
static bool factory_chip_verified;
#endif
module_param(capture_limit, uint, 0444);
MODULE_PARM_DESC(capture_limit, "Bounded image requests per root-only TLS session, 1..512");
static bool capture_quiet;
#ifdef GXFP_CHICAGO_OTP_PROBE
static bool otp_metadata_only;
module_param(otp_metadata_only, bool, 0444);
MODULE_PARM_DESC(otp_metadata_only, "One bounded factory-calibration read, numeric validation flags only; excludes TLS, image, BIOS and register writes");
#endif

/* A temporary PCI binding lets the driver core hold normal DMA-domain
 * ownership while we use its existing allocator. It never enables,
 * disables, resets, detaches or reattaches a PCI device or an IOMMU group.
 */
static struct pci_dev *ec_pci;

static int dma_guard_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	if (!map_mailbox || !iova_layout_verified || ec_pci ||
	    !dmi_match(DMI_SYS_VENDOR, "HUAWEI") ||
	    !dmi_match(DMI_PRODUCT_NAME, "MACHC-WAX9") ||
	    pci_domain_nr(pdev->bus) != 0 || pdev->bus->number != 0 ||
	    pdev->devfn != PCI_DEVFN(31, 0))
		return -ENODEV;
	ec_pci = pdev;
	return 0;
}

static void dma_guard_remove(struct pci_dev *pdev)
{
	ec_pci = NULL;
}

static const struct pci_device_id dma_guard_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, 0x0284) }, { }
};
static struct pci_driver dma_guard = {
	.name = "gxfp51b7_dma_guard", .id_table = dma_guard_ids,
	.probe = dma_guard_probe, .remove = dma_guard_remove,
};

#define LOG(fmt, ...) do { \
	if (!capture_quiet) { \
		size_t used = strlen(report); \
		scnprintf(report + used, sizeof(report) - used, fmt, ##__VA_ARGS__); \
	} \
} while (0)

struct mailbox_dma {
	struct iommu_domain *domain;
	struct iova_domain *iovad;
	struct iova *allocation;
	bool mapped;
};

static int remove_mailbox_dma(struct mailbox_dma *dma)
{
	size_t unmapped;
	unsigned int offset, remaining = 0;
	if (dma->mapped) {
		unmapped = iommu_unmap(dma->domain, 0x40200000, 0x8000);
		for (offset = 0; offset < 0x8000; offset += 0x1000)
			remaining += !!iommu_iova_to_phys(dma->domain, 0x40200000 + offset);
		LOG("mailbox_dma_unmapped_bytes=%zu remaining_mapped_pages=%u\n",
		    unmapped, remaining);
		/* Retain the IOVA reservation if removal unexpectedly failed, so
		 * another device cannot allocate an address still mapped here.
		 */
		if (remaining)
			return -EIO;
		dma->mapped = false;
	}
	if (dma->allocation) {
		__free_iova(dma->iovad, dma->allocation);
		dma->allocation = NULL;
		LOG("mailbox_iova_allocation_released=1\n");
	}
	return 0;
}

static int prepare_mailbox_dma(struct mailbox_dma *dma)
{
	unsigned int offset;
	int ret;
	/* The cookie prefix is private. Limit this research path to the
	 * reviewed kernel ABI, checked in running-kernel BTF by the runner.
	 * A production implementation needs an in-tree reserved-DMA quirk.
	 */
	static_assert(sizeof(struct iova_domain) == 128);
	static_assert(offsetof(struct iova_domain, granule) == 32);
	static_assert(offsetof(struct iova_domain, start_pfn) == 40);
	static_assert(offsetof(struct iova_domain, anchor) == 64);
	if (!ec_pci || !iova_layout_verified ||
	    strcmp(init_utsname()->release, "7.2.5-3-omarchy"))
		return -EINVAL;
	dma->domain = iommu_get_domain_for_dev(&ec_pci->dev);
	if (!dma->domain || !iommu_is_dma_domain(dma->domain) ||
	    dma->domain->cookie_type != IOMMU_COOKIE_DMA_IOVA ||
	    !dma->domain->iova_cookie)
		return -ENODEV;
	LOG("ec_dma_domain_type=0x%x cookie_type=%u\n",
	    dma->domain->type, dma->domain->cookie_type);
	/* BTF verifies that iovad is the cookie's first member at offset 0. */
	dma->iovad = (struct iova_domain *)dma->domain->iova_cookie;
	if (dma->iovad->granule != 0x1000)
		return -EINVAL;
	/* Allocate top-down with the exact mailbox end as limit. Allocation
	 * is atomic under the existing IOVA tree's lock, including cached
	 * ranges. Refuse a lower address; never merge with or replace an
	 * existing reservation or another driver's DMA allocation.
	 */
	dma->allocation = alloc_iova(dma->iovad, 8, 0x40207, false);
	if (!dma->allocation)
		return -ENOMEM;
	if (dma->allocation->pfn_lo != 0x40200 ||
	    dma->allocation->pfn_hi != 0x40207) {
		remove_mailbox_dma(dma);
		return -EBUSY;
	}
	for (offset = 0; offset < 0x8000; offset += 0x1000) {
		if (iommu_iova_to_phys(dma->domain, 0x40200000 + offset)) {
			remove_mailbox_dma(dma);
			return -EBUSY;
		}
	}
	ret = iommu_map(dma->domain, 0x40200000, 0x40200000, 0x8000,
		IOMMU_READ | IOMMU_WRITE | IOMMU_CACHE, GFP_KERNEL);
	LOG("mailbox_dma_map_error=%d bytes=32768\n", ret);
	if (ret) {
		remove_mailbox_dma(dma);
		return ret;
	}
	dma->mapped = true;
	for (offset = 0; offset < 0x8000; offset += 0x1000) {
		if (iommu_iova_to_phys(dma->domain, 0x40200000 + offset) != 0x40200000 + offset) {
			remove_mailbox_dma(dma);
			return -EIO;
		}
	}
	LOG("mailbox_dma_identity_verified_pages=8\n");
	return 0;
}

struct mailbox_observer {
	u8 *before;
	u8 *after;
	atomic_t interrupts;
	atomic_t irq_disabled;
	int irq;
	struct chicago_control_snapshot control;
};
static struct mailbox_observer *observer;

static irqreturn_t observe_interrupt(int irq, void *data)
{
	struct mailbox_observer *o = data;
	/* Hold a level IRQ until the receive code acknowledges its frame. */
	disable_irq_nosync(irq);
	atomic_set(&o->irq_disabled, 1);
	chicago_control_snapshot_irq(&o->control);
	atomic_inc_return(&o->interrupts);
	return IRQ_HANDLED;
}

static void rearm_observer(struct gpio_desc *irq)
{
	if (!observer)
		return;
	synchronize_irq(observer->irq);
	if (gpiod_get_raw_value_cansleep(irq) != 1)
		return;
	if (atomic_xchg(&observer->irq_disabled, 0))
		enable_irq(observer->irq);
}

static void report_mailbox_changes(void __iomem *mmio)
{
	unsigned int i, count = 0, page_mask = 0;
	if (!observer)
		return;
	memcpy_fromio(observer->after, mmio, 0x8000);
	for (i = 0; i < 0x8000; i++) {
		if (observer->before[i] != observer->after[i]) {
			count++;
			page_mask |= 1U << (i >> 12);
		}
	}
	LOG("mailbox_changed_bytes=%u changed_pages=0x%x observed_interrupts=%d\n",
	    count, page_mask, atomic_read(&observer->interrupts));
	/* Neither mailbox contents nor possible personal data are reported. */
	memzero_explicit(observer->before, 0x8000);
	memzero_explicit(observer->after, 0x8000);
}

static void scan_mailbox_hashes(void __iomem *mmio)
{
	/* The EC modifies substantially more RX memory than its 56-byte hello.
	 * This tests a hypothesis about residual mailbox data. It never writes
	 * to the mailbox, dumps bytes, or treats a digest match as TLS success.
	 */
	static const unsigned int lengths[] = { 3, 16, 24, 32, 48, 64, 96, 100 };
	u8 digest[SHA256_DIGEST_SIZE];
	unsigned int i, at, matches;
	if (!observer || !pmk_digest_valid)
		return;
	memcpy_fromio(observer->after, mmio, 0x8000);
	for (i = 0; i < ARRAY_SIZE(lengths); i++) {
		matches = 0;
		for (at = 0; at + lengths[i] <= 0x8000; at++) {
			sha256(observer->after + at, lengths[i], digest);
			matches += !memcmp(digest, pmk_digest, sizeof(digest));
			if (!(at & 0x1ff))
				cond_resched();
		}
		LOG("mailbox_sha256_window_length=%u match_count=%u\n", lengths[i], matches);
	}
	memzero_explicit(digest, sizeof(digest));
	memzero_explicit(observer->after, 0x8000);
	LOG("mailbox_candidate_scan_completed=1 scanned_bytes=32768 raw_values_logged=0\n");
}

static const struct acpi_gpio_params irq_gpio = { 0, 0, false };
static const struct acpi_gpio_params ack_gpio = { 1, 0, false };
static const struct acpi_gpio_mapping gpio_map[] = {
	{ "irq-gpios", &irq_gpio, 1 },
	{ "ack-gpios", &ack_gpio, 1 },
	{ }
};

struct crs_check { unsigned int gpios; bool valid; };

static int inspect_bios_key(acpi_handle handle)
{
	union acpi_object *obj;
	struct blob_metadata metadata;
	acpi_handle guard;
	int classification;
	LOG("dsm3_guard_present=%u\n", ACPI_SUCCESS(acpi_get_handle(NULL,
	    "\\_SB.PCI0.LPCB.H_EC.ECMD", &guard)));
	obj = acpi_evaluate_dsm_typed(handle, &goodix_guid, 0, 1, NULL,
	    ACPI_TYPE_BUFFER);
	if (!obj)
		return -EIO;
	LOG("bios_blob_length=%u\n", obj->buffer.length);
	if (obj->buffer.length != 0x800 || !obj->buffer.pointer) {
		if (obj->buffer.pointer)
			memzero_explicit(obj->buffer.pointer, obj->buffer.length);
		ACPI_FREE(obj);
		return -EINVAL;
	}
	classification = blob_parse_metadata(obj->buffer.pointer,
	    obj->buffer.length, &metadata);
	LOG("bios_container_bounded=%u bios_container_length=%u sgx_structure_consistent=%u\n",
	    classification > 0, metadata.container_len, classification == 2);
	if (classification == 2)
		LOG("seal_key_selector=%u seal_key_policy=%u sealed_payload_length=%u encrypted_length=%u\n",
		    metadata.key_name, metadata.key_policy,
		    metadata.payload_len, metadata.encrypted_len);
	/* Erase the ACPI interpreter's returned copy, not BIOS persistent data. */
	memzero_explicit(obj->buffer.pointer, obj->buffer.length);
	ACPI_FREE(obj);
	LOG("bios_copy_erased=1 sensor_commands_sent=0\n");
	return 0;
}

static void ec_status(const char *stage)
{
	unsigned long long available, command;
	acpi_status a, b;
	a = acpi_evaluate_integer(NULL, "\\_SB.PCI0.LPCB.HWEC.ECAV", NULL, &available);
	b = acpi_evaluate_integer(NULL, "\\_SB.PCI0.LPCB.HWEC.CMDR", NULL, &command);
	if (ACPI_SUCCESS(a) && ACPI_SUCCESS(b))
		LOG("ec_stage=%s available=%llu command_register=0x%llx\n", stage, available, command);
	else
		LOG("ec_stage=%s read_status=%u,%u\n", stage, a, b);
}

static int ec_notification(unsigned int command)
{
	union acpi_object argument = { .integer = {
		.type = ACPI_TYPE_INTEGER, .value = command } };
	struct acpi_object_list arguments = { 1, &argument };
	unsigned long long value = 0xff;
	acpi_status status;

	/* These two notifications are declared in this device's BIOS DSM3/4.
	 * Their undocumented EC semantics must be measured, not assumed.
	 */
	if (command != 0xf1 && command != 0xf2)
		return -EINVAL;
	status = acpi_evaluate_integer(NULL, "\\_SB.PCI0.LPCB.HWEC.ECMD",
		&arguments, &value);
	LOG("ec_%02x_evaluation_status=%u ec_%02x_return=%llu\n",
	    command, status, command, value);
	return ACPI_SUCCESS(status) && value == 0 ? 0 : -EIO;
}

static acpi_status check_resource(struct acpi_resource *res, void *context)
{
	struct crs_check *c = context;
	struct acpi_resource_gpio *g;
	unsigned int index;
	if (res->type != ACPI_RESOURCE_TYPE_GPIO)
		return AE_OK;
	g = &res->data.gpio;
	index = c->gpios++;
	if (index > 1 || g->pin_table_length != 1 ||
	    !g->resource_source.string_ptr ||
	    strcmp(g->resource_source.string_ptr, "\\_SB.PCI0.GPI0")) {
		c->valid = false;
		return AE_OK;
	}
	LOG("gpio%u_pin=%u type=%u polarity=%u trigger=%u restriction=%u\n",
	    index, g->pin_table[0], g->connection_type, g->polarity,
	    g->triggering, g->io_restriction);
	if (index == 0 && (g->connection_type != ACPI_RESOURCE_GPIO_TYPE_INT ||
	    g->polarity != ACPI_ACTIVE_LOW || g->triggering != ACPI_LEVEL_SENSITIVE))
		c->valid = false;
	if (index == 1 && (g->connection_type != ACPI_RESOURCE_GPIO_TYPE_IO ||
	    g->io_restriction != ACPI_IO_RESTRICT_OUTPUT))
		c->valid = false;
	return AE_OK;
}

static void acknowledge(struct gpio_desc *ack)
{
	/* ISR writes low; worker raises high after the minimum five-ms hold. */
	gpiod_set_raw_value_cansleep(ack, 0);
	usleep_range(5000, 6000);
	gpiod_set_raw_value_cansleep(ack, 1);
}

static int exchange(void __iomem *mmio, acpi_handle handle,
		    struct gpio_desc *irq, struct gpio_desc *ack,
		    const unsigned char *request, unsigned int request_len)
{
	unsigned char previous[512], rx_frame[512];
	union acpi_object *obj;
	unsigned long deadline;
	unsigned int n, frames = 0, changed = 0, edges = 0, invalid = 0;
	unsigned int chip_id;
	int level, last_level, found = 0, interrupts, last_interrupts;
	u8 command = request[4];

	if (request_len > sizeof(rx_frame) || !frame_valid(request, request_len))
		return -EINVAL;
	last_level = gpiod_get_raw_value_cansleep(irq);
	if (last_level < 0)
		return last_level;
	memcpy_fromio(previous, mmio + 0x1000, sizeof(previous));
	memcpy_toio(mmio, request, request_len);
	wmb();
	memcpy_fromio(rx_frame, mmio, request_len);
	if (memcmp(rx_frame, request, request_len)) {
		LOG("tx_readback_mismatch=1\n");
		return -EIO;
	}
	LOG("tx_readback_matches=1\n");
	/* Start after our own request write, so it is not counted as an EC reply. */
	if (observer)
		memcpy_fromio(observer->before, mmio, 0x8000);
	last_interrupts = observer ? atomic_read(&observer->interrupts) : 0;
	obj = acpi_evaluate_dsm(handle, &goodix_guid, 0, 2, NULL);
	LOG("tx_command=0x%02x dsm2_completed=%u\n", command, !!obj);
	if (!obj)
		return -EIO;
	ACPI_FREE(obj);
	ec_status("after_dsm2");
	deadline = jiffies + msecs_to_jiffies(2000);
	while (time_before(jiffies, deadline) && frames < 8) {
		bool different, falling, interrupted;
		usleep_range(1000, 2000);
		level = gpiod_get_raw_value_cansleep(irq);
		if (level < 0)
			return level;
		falling = last_level == 1 && level == 0;
		edges += level != last_level;
		last_level = level;
		memcpy_fromio(rx_frame, mmio + 0x1000, sizeof(rx_frame));
		different = memcmp(rx_frame, previous, sizeof(rx_frame)) != 0;
		interrupts = observer ? atomic_read(&observer->interrupts) : 0;
		interrupted = interrupts != last_interrupts;
		last_interrupts = interrupts;
		/* An identical ACK is still a fresh reply when a new IRQ arrives. */
		if (!different && !falling && !interrupted)
			continue;
		changed += different;
		memcpy(previous, rx_frame, sizeof(previous));
		n = frame_length(rx_frame, sizeof(rx_frame));
		if (!n || (!frame_valid(rx_frame, n) && !frame_tls_record(rx_frame, n))) {
			invalid++;
			/* Do not acknowledge a partially written or unrelated frame. */
			continue;
		}
		frames++;
		if (scan_mailbox_candidates && command == 0xd0 &&
		    (rx_frame[0] & 0xf0) == 0xb0)
			scan_mailbox_hashes(mmio);
		acknowledge(ack);
		rearm_observer(irq);
		if ((rx_frame[0] & 0xf0) == 0xb0) {
			struct tls_hello_metadata hello;
			unsigned int i, count;
			LOG("rx_tls_packet_bytes=%u record_type=%u\n", n, rx_frame[4]);
			if (command != 0xd0 || !frame_tls_client_hello(rx_frame, n, &hello))
				continue;
			LOG("tls_record_version=0x%04x tls_client_version=0x%04x\n",
			    hello.record_version, hello.client_version);
			LOG("tls_cipher_count=%u tls_extensions=%u tls_extended_master_secret=%u tls_null_compression=%u\n",
			    hello.cipher_bytes / 2, hello.extensions,
			    hello.extended_master_secret, hello.null_compression);
			count = min(hello.cipher_bytes / 2, 32U);
			for (i = 0; i < count; i++)
				LOG("tls_offered_cipher_%u=0x%04x\n", i, tls_u16be(hello.ciphers + 2 * i));
			LOG("tls_client_hello_metadata_verified=1 tls_key_used=0 tls_random_logged=0\n");
			found = 1;
			break;
		}
		LOG("rx_command=0x%02x bytes=%u irq_raw=%d\n", rx_frame[4], n, level);
		if (rx_frame[4] == 0xb0 && n >= 9 && rx_frame[7] == command)
			LOG("command_ack=0x%02x\n", command);
		if (command == 0x90 && frame_chip_id(rx_frame, n, &chip_id)) {
			LOG("chip_id=0x%04x\n", chip_id);
			found = 1;
			break;
		}
		if (command == 0x96 && rx_frame[4] == 0xb0 && n >= 9 &&
		    rx_frame[7] == command) {
			/* This confirms a matching message, not a successful enrollment
			 * or even the meaning of any additional status bytes. */
			LOG("driver_state_message_received=1\n");
			found = 1;
			break;
		}
		if (command == 0xd4 && rx_frame[4] == 0xb0 && n >= 9 &&
		    rx_frame[7] == command) {
			LOG("tls_finish_message_received=1\n");
			found = 1;
			break;
		}
		if (rx_frame[4] != command)
			continue;
		if (command == 0x82 && frame_register_chip_id(rx_frame, n, &chip_id)) {
#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
			factory_chip_verified = chip_id == 0x002504;
#endif
			LOG("chip_id_bytes=%4phN\n", rx_frame + 7);
			LOG("register_chip_id=0x%06x register_chip_id_verified=1\n", chip_id);
			found = 1;
		} else if (command == 0xa8 && n > 8 && n <= 72) {
			char version[65];
			unsigned int i, len = n - 8;
			bool printable = true;
			for (i = 0; i < len; i++) {
				if (!rx_frame[7 + i])
					break;
				if (rx_frame[7 + i] < 32 || rx_frame[7 + i] > 126)
					printable = false;
				version[i] = rx_frame[7 + i];
			}
			version[i] = 0;
			if (printable && i) {
				LOG("firmware_version=%s\n", version);
				LOG("firmware_version_verified=1\n");
				found = 1;
			}
		} else if (command == 0xae && n == 18) {
			/* GetMcuState copies ten bytes without byte swapping.
			 * _TlsInitAndHandShake decodes these five flags at 0x18002a0dc.
			 */
			LOG("mcu_state_bytes=%10phN\n", rx_frame + 7);
			LOG("mcu_image_valid=%u mcu_tls_connected=%u mcu_spi_send=%u mcu_locked=%u mcu_pba_support=%u\n",
			    rx_frame[7] & 1, (rx_frame[7] >> 1) & 1,
			    (rx_frame[7] >> 2) & 1, (rx_frame[7] >> 3) & 1,
			    rx_frame[9] & 1);
			LOG("mcu_state_verified=1\n");
			last_mcu_tls_connected = !!(rx_frame[7] & 2);
			found = 1;
		} else if (command == 0xe4) {
			const u8 *data;
			unsigned int status, len, hash_len;
			if (frame_pmk_hash_result(rx_frame, n, &status, &data, &len)) {
				LOG("pmk_hash_response_status=%u data_bytes=%u\n", status, len);
				if (!status && len >= 8 && frame_u32le(data + 4) == len - 8) {
					u8 zeros[48] = { }, digest[SHA256_DIGEST_SIZE];
					static const u8 enclave_default[] = { 0x12, 0x34, 0x56 };
					hash_len = frame_u32le(data + 4);
					LOG("pmk_hash_container_type=0x%08x hash_bytes=%u\n",
					    frame_u32le(data), hash_len);
					if (hash_len == SHA256_DIGEST_SIZE) {
						if (scan_mailbox_candidates) {
							memcpy(pmk_digest, data + 8, sizeof(pmk_digest));
							pmk_digest_valid = true;
						}
						sha256(zeros, 48, digest);
						LOG("pmk_hash_matches_48_zero_bytes=%u\n",
						    !memcmp(data + 8, digest, sizeof(digest)));
						sha256(zeros, 32, digest);
						LOG("pmk_hash_matches_32_zero_bytes=%u\n",
						    !memcmp(data + 8, digest, sizeof(digest)));
						/* WBDI_Enclave TLS_Server_Init uses these three
						 * public fallback bytes at 0x180007b22/0x180007b40.
						 */
						sha256(enclave_default, sizeof(enclave_default), digest);
						LOG("pmk_hash_matches_enclave_fallback=%u\n",
						    !memcmp(data + 8, digest, sizeof(digest)));
					}
					memzero_explicit(digest, sizeof(digest));
					LOG("pmk_hash_metadata_verified=1 hash_contents_logged=0\n");
					found = 1;
				}
			}
		} else if (command == 0xa2) {
			LOG("reset_reply_received=1\n");
			found = 1;
		}
		if (found)
			break;
	}
	LOG("command=0x%02x valid_frames=%u mmio_changes=%u irq_edges=%u invalid=%u result=%s\n",
	    command, frames, changed, edges, invalid, found ? "reply" : "no_matching_reply");
	if (command == 0x90)
		LOG("chip_id_verified=%u\n", found);
	report_mailbox_changes(mmio);
	ec_status("after_receive");
	if (!found) {
		/* Original SpiSendDataToDeviceLock calls TriggerDriverOutGPIO
		 * on missing EC ACK/data: 0x180050256 and 0x1800504a0. */
		acknowledge(ack);
		msleep(20);
		rearm_observer(irq);
		LOG("timeout_recovery_pulse=1 irq_after=%d\n", gpiod_get_raw_value_cansleep(irq));
	}
	return found || command == 0x90 ? 0 : -ETIMEDOUT;
}

#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
#include "chicago_factory_bus.h"
#endif
#include "tls_stream.h"
#ifdef GXFP_CHICAGO_OTP_PROBE
#include "chicago_otp_query.h"
#endif

static int native_probe(struct platform_device *pdev)
{
	/* GetEvkVersion at 0x18004d8d0 uses command A8 and two payload bytes.
	 * Those bytes are uninitialized in that binary; use the known GXFP5187
	 * query values. ChipRegRead and reset are exact bytes from our binary. */
	static const u8 chip[] = { 0xa0, 9, 0, 0xa9, 0x82, 6, 0, 0, 0, 0, 4, 0, 0x1e };
	/* Exact request published in OpenGoodixSPI #16, section 3.4.
	 * Not yet verified against this machine or our driver's 1.1.151.18.
	 */
	static const u8 chip_query[] = { 0xa0, 4, 0, 0xa4, 0x90, 1, 0, 0x19 };
	static const u8 version[] = { 0xa0, 6, 0, 0xa6, 0xa8, 3, 0, 0x70, 0xdc, 0xb3 };
	static const u8 reset[] = { 0xa0, 6, 0, 0xa6, 0xa2, 3, 0, 5, 0x14, 0xec };
	/* SetDriverState (0x18004f7a8): category 9, subcommand 3;
	 * a zeroed two-byte payload receives the state in byte zero.
	 * _DeviceInit calls state 1 before GetEvkVersionWithRetry.
	 * MilanEvtDeviceQueryRemove calls the same function with state 0.
	 */
	static const u8 loaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 1, 0, 0x10 };
	static const u8 unloaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 0, 0, 0x11 };
	/* GetMcuState at 0x18004dcf8: category A, subcommand 7, payload 55.
	 * This getter does not initiate TLS or write a key/configuration.
	 */
	static const u8 get_state[] = { 0xa0, 5, 0, 0xa5, 0xae, 2, 0, 0x55, 0xa5 };
	/* ProductionReadPmkHash (0x18003cad2) calls ProductionOperateKey with
	 * operation 2 and no input payload. Only that getter is exposed here;
	 * no write/reset operation is constructed or sent.
	 */
	static const u8 get_pmk_hash[] = { 0xa0, 4, 0, 0xa4, 0xe4, 1, 0, 0xc5 };
	/* TLSServerInit 0x180027174 sends D0 with two zero bytes. Its timeout
	 * path calls 0x1800270f4: D4 with two zero bytes, then GetMcuState.
	 * This diagnostic reads only the unauthenticated initial ClientHello.
	 */
	static const u8 tls_start[] = { 0xa0, 6, 0, 0xa6, 0xd0, 3, 0, 0, 0, 0xd7 };
	static const u8 tls_finish[] = { 0xa0, 6, 0, 0xa6, 0xd4, 3, 0, 0, 0, 0xd3 };
	struct device *dev = &pdev->dev;
	acpi_handle handle = ACPI_HANDLE(dev);
	struct resource *mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct crs_check c = { .valid = true };
	struct gpio_desc *irq, *ack;
	union acpi_object *obj;
	void __iomem *mmio;
	int ret = -ENODEV, initial, direction, irq_initial, cleanup_ret, irq_number;
	unsigned int bitmap = 0;
	bool ec_f1_invoked = false;
	struct mailbox_dma dma = { };

	report[0] = 0;
	LOG("device=%s run=%u reset_first=%u chip_id_only=%u driver_startup=%u observe_mailbox=%u\n",
	    dev_name(dev), run, reset_first, chip_id_only, driver_startup, observe_mailbox);
#ifdef GXFP_CHICAGO_OTP_PROBE
	if (!otp_metadata_only || !run || !driver_startup || !observe_mailbox ||
	    !map_mailbox || !iova_layout_verified || reset_first || chip_id_only ||
	    mcu_state || pmk_hash_metadata || tls_hello_metadata || scan_mailbox_candidates ||
	    key_metadata || wake_first || ec_f2_only || tls_stream || capture_limit != 1) {
		ret = -EINVAL;
		goto done;
	}
#endif

#ifdef GXFP_CHICAGO_FACTORY_CAPTURE
	const struct gxfp_factory_startup_options factory_options = {
		.run = run, .driver_startup = driver_startup,
		.observe_mailbox = observe_mailbox, .map_mailbox = map_mailbox,
		.iova_layout_verified = iova_layout_verified, .tls_stream = tls_stream,
		.reset_first = reset_first, .chip_id_only = chip_id_only,
		.mcu_state = mcu_state, .pmk_hash_metadata = pmk_hash_metadata,
		.tls_hello_metadata = tls_hello_metadata,
		.scan_mailbox_candidates = scan_mailbox_candidates,
		.key_metadata = key_metadata, .wake_first = wake_first,
		.ec_f2_only = ec_f2_only, .capture_limit = capture_limit,
	};
	if (!gxfp_factory_startup_valid(&factory_options)) {
		LOG("failed_stage=factory_startup_policy capture_limit=%u required_capture_limit=%u\n",
		    capture_limit, GXFP_FACTORY_REQUIRED_CAPTURE_LIMIT);
		ret = -EINVAL;
		goto done;
	}
#endif
	if ((chip_id_only && (!run || reset_first)) ||
	    (driver_startup && (!run || reset_first || chip_id_only)) ||
	    (observe_mailbox && !run) || (key_metadata && run) ||
	    (wake_first && !driver_startup) ||
	    (mcu_state && !driver_startup) ||
	    (pmk_hash_metadata && !driver_startup) ||
	    (tls_hello_metadata && (!driver_startup || pmk_hash_metadata || mcu_state)) ||
	    (scan_mailbox_candidates && (!tls_hello_metadata || !observe_mailbox)) ||
	    (ec_f2_only && (run || key_metadata)) ||
	    (tls_stream && (!driver_startup || !map_mailbox || !observe_mailbox ||
	                   wake_first || mcu_state || pmk_hash_metadata ||
	                   tls_hello_metadata || scan_mailbox_candidates)) ||
	    (!capture_limit || capture_limit > 512 || (capture_limit != 1 && !tls_stream)) ||
	    (map_mailbox && (!run || !iova_layout_verified))) {
		ret = -EINVAL;
		goto done;
	}
	if (!dmi_match(DMI_SYS_VENDOR, "HUAWEI") ||
	    !dmi_match(DMI_PRODUCT_NAME, "MACHC-WAX9") || !handle || !mem ||
	    mem->start != 0x40200000 || resource_size(mem) != 0x8000)
		goto done;
	LOG("mmio_start=0x%llx mmio_size=0x%llx\n",
	    (unsigned long long)mem->start, (unsigned long long)resource_size(mem));
	if (ACPI_FAILURE(acpi_walk_resources(handle, METHOD_NAME__CRS, check_resource, &c)) ||
	    !c.valid || c.gpios != 2)
		goto done;
	obj = acpi_evaluate_dsm_typed(handle, &goodix_guid, 0, 0, NULL, ACPI_TYPE_BUFFER);
	if (!obj)
		goto done;
	if (obj->buffer.length)
		bitmap = obj->buffer.pointer[0];
	ACPI_FREE(obj);
	LOG("dsm_bitmap=0x%x\n", bitmap);
	if ((bitmap & 5) != 5)
		goto done;
	if (key_metadata) {
		if (!(bitmap & 2))
			goto done;
		ret = inspect_bios_key(handle);
		goto done;
	}
	ret = 0;
	if (!run && !ec_f2_only)
		goto done;
	ec_status("before_test");
	ret = devm_acpi_dev_add_driver_gpios(dev, gpio_map);
	if (ret)
		goto done;
	irq = devm_gpiod_get(dev, "irq", GPIOD_IN);
	if (IS_ERR(irq)) {
		ret = PTR_ERR(irq);
		LOG("failed_stage=irq_gpio\n");
		goto done;
	}
	ack = devm_gpiod_get(dev, "ack", GPIOD_ASIS);
	if (IS_ERR(ack)) {
		ret = PTR_ERR(ack);
		LOG("failed_stage=ack_gpio\n");
		goto done;
	}
	initial = gpiod_get_raw_value_cansleep(ack);
	direction = gpiod_get_direction(ack);
	irq_initial = gpiod_get_raw_value_cansleep(irq);
	LOG("ack_initial=%d ack_direction=%d irq_initial=%d\n", initial, direction, irq_initial);
	if (initial < 0 || direction != 0 || irq_initial < 0) {
		ret = -EINVAL;
		goto done;
	}
	if (ec_f2_only) {
		ret = ec_notification(0xf2);
		msleep(20);
		LOG("irq_20ms_after_ec_f2=%d\n", gpiod_get_raw_value_cansleep(irq));
		msleep(200);
		cleanup_ret = gpiod_get_raw_value_cansleep(irq);
		LOG("irq_220ms_after_ec_f2=%d sensor_commands_sent=0 mailbox_writes=0\n",
		    cleanup_ret);
		if (!ret && cleanup_ret != 1)
			ret = -EIO;
		ec_status("after_ec_f2");
		goto done;
	}
	mmio = devm_ioremap_resource(dev, mem);
	if (IS_ERR(mmio)) {
		ret = PTR_ERR(mmio);
		goto done;
	}
	if (map_mailbox) {
		ret = prepare_mailbox_dma(&dma);
		if (ret) {
			LOG("failed_stage=mailbox_dma_map\n");
			goto restore;
		}
	}
	gpiod_set_raw_value_cansleep(ack, 1);
	msleep(20);
	if (gpiod_get_raw_value_cansleep(irq) == 0) {
		/* Original ISR also pulses ACK for invalid/stale receive headers. */
		acknowledge(ack);
		msleep(20);
		LOG("pending_irq_acknowledged=1 irq_after=%d\n", gpiod_get_raw_value_cansleep(irq));
	}
	if (observe_mailbox) {
		observer = devm_kzalloc(dev, sizeof(*observer), GFP_KERNEL);
		if (!observer) {
			ret = -ENOMEM;
			goto restore;
		}
		observer->before = devm_kzalloc(dev, 0x8000, GFP_KERNEL);
		observer->after = devm_kzalloc(dev, 0x8000, GFP_KERNEL);
		if (!observer->before || !observer->after) {
			ret = -ENOMEM;
			goto restore;
		}
		atomic_set(&observer->interrupts, 0);
		atomic_set(&observer->irq_disabled, 0);
		chicago_control_snapshot_init(&observer->control);
		irq_number = gpiod_to_irq(irq);
		if (irq_number < 0) {
			ret = irq_number;
			goto restore;
		}
		observer->irq = irq_number;
		ret = devm_request_threaded_irq(dev, irq_number, NULL,
			observe_interrupt, IRQF_TRIGGER_LOW | IRQF_ONESHOT,
			"gxfp51b7_observer", observer);
		LOG("irq_number=%d irq_registration_error=%d\n", irq_number, ret);
		if (ret)
			goto restore;
	}
	if (wake_first) {
		/* SSDT11 DSM3 contains this exact EC call, but its H_EC guard is
		 * absent on this computer. This is an EC notification, not a
		 * Goodix category-F firmware command. Its purpose is reported as
		 * wake/attention in OpenGoodixSPI #16; verify effects here rather
		 * than treating the AML return as a response from the sensor.
		 */
		ec_f1_invoked = true;
		ret = ec_notification(0xf1);
		if (ret) {
			goto restore;
		}
		msleep(20);
		LOG("irq_after_ec_f1=%d\n", gpiod_get_raw_value_cansleep(irq));
		if (gpiod_get_raw_value_cansleep(irq) == 0) {
			acknowledge(ack);
			msleep(20);
			LOG("ec_f1_pending_irq_acknowledged=1\n");
		}
		if (observer && atomic_read(&observer->interrupts) &&
		    gpiod_get_raw_value_cansleep(irq) == 1) {
			rearm_observer(irq);
			LOG("irq_observer_rearmed_after_ec_f1=1\n");
		}
		ec_status("after_ec_f1");
	}
	if (chip_id_only) {
		ret = exchange(mmio, handle, irq, ack, chip_query, sizeof(chip_query));
		goto restore;
	}
	if (tls_stream) {
		ret = stream_register(dev, mmio, handle, irq, ack, initial, &dma);
		if (ret)
			goto restore;
		/* Runtime owns this exact reservation until platform remove. */
		LOG("probe_completed=1 error=0 tls_stream_registered=1\n");
		return 0;
	}
	if (driver_startup) {
		LOG("startup_stage=driver_loaded\n");
		ret = exchange(mmio, handle, irq, ack, loaded, sizeof(loaded));
		if (!ret) {
			LOG("startup_stage=version\n");
			ret = exchange(mmio, handle, irq, ack, version, sizeof(version));
		}
		if (!ret) {
			LOG("startup_stage=register_id\n");
			ret = exchange(mmio, handle, irq, ack, chip, sizeof(chip));
		}
#ifdef GXFP_CHICAGO_OTP_PROBE
		if (!ret) ret = chicago_otp_query(mmio, handle, irq, ack);
		/* End the driver's loaded state on success and on query failure. */
		{
			static const u8 unloaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 0, 0, 0x11 };
			cleanup_ret = exchange(mmio, handle, irq, ack, unloaded, sizeof(unloaded));
			LOG("otp_driver_unload_error=%d\n", cleanup_ret);
			if (!ret) ret = cleanup_ret;
		}
		goto restore;
#endif
		if (!ret && mcu_state) {
			LOG("startup_stage=mcu_state\n");
			ret = exchange(mmio, handle, irq, ack, get_state, sizeof(get_state));
		}
		if (!ret && pmk_hash_metadata) {
			LOG("startup_stage=pmk_hash_metadata\n");
			ret = exchange(mmio, handle, irq, ack, get_pmk_hash, sizeof(get_pmk_hash));
		}
		if (!ret && tls_hello_metadata) {
			if (scan_mailbox_candidates) {
				LOG("startup_stage=pmk_hash_for_mailbox_comparison\n");
				ret = exchange(mmio, handle, irq, ack, get_pmk_hash, sizeof(get_pmk_hash));
				if (!ret && !pmk_digest_valid)
					ret = -EINVAL;
			}
		}
		if (!ret && tls_hello_metadata) {
			LOG("startup_stage=tls_state_before\n");
			last_mcu_tls_connected = -1;
			ret = exchange(mmio, handle, irq, ack, get_state, sizeof(get_state));
			if (!ret && last_mcu_tls_connected != 0) {
				LOG("tls_start_refused_existing_session=1\n");
				ret = -EBUSY;
			}
			if (!ret) {
				LOG("startup_stage=tls_client_hello\n");
				ret = exchange(mmio, handle, irq, ack, tls_start, sizeof(tls_start));
				/* Finish even if metadata parsing or ClientHello receive failed. */
				LOG("startup_stage=tls_finish\n");
				cleanup_ret = exchange(mmio, handle, irq, ack, tls_finish, sizeof(tls_finish));
				if (!ret)
					ret = cleanup_ret;
				LOG("startup_stage=tls_state_after\n");
				last_mcu_tls_connected = -1;
				cleanup_ret = exchange(mmio, handle, irq, ack, get_state, sizeof(get_state));
				if (!cleanup_ret && last_mcu_tls_connected == 0)
					LOG("mcu_tls_disconnected_after_metadata=1\n");
				else if (!cleanup_ret)
					cleanup_ret = -EIO;
				if (!ret)
					ret = cleanup_ret;
			}
		}
		LOG("startup_stage=driver_unloaded\n");
		cleanup_ret = exchange(mmio, handle, irq, ack, unloaded, sizeof(unloaded));
		if (!ret)
			ret = cleanup_ret;
		goto restore;
	}
	if (reset_first) {
		ret = exchange(mmio, handle, irq, ack, reset, sizeof(reset));
		if (ret)
			goto restore;
		msleep(100);
	}
	ret = exchange(mmio, handle, irq, ack, chip, sizeof(chip));
	if (!ret)
		ret = exchange(mmio, handle, irq, ack, version, sizeof(version));
restore:
	memzero_explicit(pmk_digest, sizeof(pmk_digest));
	pmk_digest_valid = false;
	if (observer) {
		if (observer->before)
			memzero_explicit(observer->before, 0x8000);
		if (observer->after)
			memzero_explicit(observer->after, 0x8000);
		LOG("observed_interrupts_total=%d\n", atomic_read(&observer->interrupts));
	}
	if (ec_f1_invoked) {
		cleanup_ret = ec_notification(0xf2);
		if (!ret)
			ret = cleanup_ret;
		msleep(220);
		LOG("irq_after_ec_f2_cleanup=%d irq_initial=%d\n",
		    gpiod_get_raw_value_cansleep(irq), irq_initial);
		ec_status("after_ec_f2_cleanup");
	}
	gpiod_set_raw_value_cansleep(ack, initial);
	LOG("ack_restored=%d\n", gpiod_get_raw_value_cansleep(ack));
done:
	cleanup_ret = remove_mailbox_dma(&dma);
	if (!ret)
		ret = cleanup_ret;
	LOG("probe_completed=1 error=%d\n", ret);
	/* Keep the bounded report readable even when a diagnostic stage fails. */
	return 0;
}

static const struct acpi_device_id native_ids[] = { { "GXFP51B7", 0 }, { } };
MODULE_DEVICE_TABLE(acpi, native_ids);
static struct platform_driver native_driver = {
	.probe = native_probe,
	.remove = stream_remove,
	.driver = {
#ifdef GXFP_CHICAGO_OTP_PROBE
	            .name = "gxfp51b7_otp",
#elif defined(GXFP_ORIGINAL_ENGINE_IDENTITY)
	            .name = "gxfp51b7_engine",
#elif defined(GXFP_CHICAGO_FACTORY_CAPTURE)
	            .name = "gxfp51b7_factory",
#else
	            .name = "gxfp51b7_native",
#endif
	            .acpi_match_table = native_ids,
	            .suppress_bind_attrs = true },
};
static int __init native_init(void)
{
	int ret;
	if (map_mailbox) {
		ret = pci_register_driver(&dma_guard);
		if (ret)
			return ret;
		if (!ec_pci) {
			pci_unregister_driver(&dma_guard);
			return -EBUSY;
		}
	}
	ret = platform_driver_register(&native_driver);
	if (ret && map_mailbox)
		pci_unregister_driver(&dma_guard);
	return ret;
}

static void __exit native_exit(void)
{
	memzero_explicit(pmk_digest, sizeof(pmk_digest));
	platform_driver_unregister(&native_driver);
	if (map_mailbox)
		pci_unregister_driver(&dma_guard);
}
module_init(native_init);
module_exit(native_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Bounded GXFP51B7 EC/GPIO native transport diagnostic");
