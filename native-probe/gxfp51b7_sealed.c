// SPDX-License-Identifier: GPL-2.0-only
/* Temporary read-only transfer of this machine's encrypted BIOS container.
 * No sensor, GPIO, mailbox, PCI, key-write or firmware-write operations.
 * Root can read only a format-checked SGX sealed object, never plaintext.
 */
#include <linux/acpi.h>
#include <linux/capability.h>
#include <linux/dmi.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include "blob.h"

static const guid_t goodix_guid = GUID_INIT(0xcc58b68a, 0x4479, 0x4893,
	0xa8, 0xbb, 0x96, 0x12, 0x09, 0xdb, 0x59, 0xe5);
static u8 *sealed_copy;
static unsigned int sealed_length;
module_param(sealed_length, uint, 0444);

static ssize_t sealed_read(struct file *file, struct kobject *kobj,
			   const struct bin_attribute *attr, char *out,
			   loff_t offset, size_t count)
{
	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (offset < 0)
		return -EINVAL;
	if (!sealed_copy || offset >= sealed_length)
		return 0;
	count = min_t(size_t, count, sealed_length - offset);
	memcpy(out, sealed_copy + offset, count);
	return count;
}

static struct bin_attribute sealed_attribute = {
	.attr = { .name = "sgx_sealed", .mode = 0400 },
	.read = sealed_read,
};

static int sealed_probe(struct platform_device *pdev)
{
	struct resource *mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	struct blob_metadata metadata;
	union acpi_object *obj;
	acpi_handle handle = ACPI_HANDLE(&pdev->dev);
	int ret = -EINVAL;

	if (sealed_copy || !dmi_match(DMI_SYS_VENDOR, "HUAWEI") ||
	    !dmi_match(DMI_PRODUCT_NAME, "MACHC-WAX9") || !handle || !mem ||
	    mem->start != 0x40200000 || resource_size(mem) != 0x8000)
		return -ENODEV;
	obj = acpi_evaluate_dsm_typed(handle, &goodix_guid, 0, 1, NULL,
				    ACPI_TYPE_BUFFER);
	if (!obj)
		return -EIO;
	if (obj->buffer.pointer && obj->buffer.length == 0x800 &&
	    blob_parse_metadata(obj->buffer.pointer, obj->buffer.length,
				&metadata) == 2 && metadata.key_policy == 2) {
		sealed_copy = kmemdup(obj->buffer.pointer + 4,
				      metadata.container_len, GFP_KERNEL);
		if (!sealed_copy) {
			ret = -ENOMEM;
		} else {
			sealed_length = metadata.container_len;
			sealed_attribute.size = sealed_length;
			ret = sysfs_create_bin_file(&pdev->dev.kobj, &sealed_attribute);
			if (ret) {
				kfree_sensitive(sealed_copy);
				sealed_copy = NULL;
				sealed_length = 0;
			}
		}
	}
	if (obj->buffer.pointer)
		memzero_explicit(obj->buffer.pointer, obj->buffer.length);
	ACPI_FREE(obj);
	return ret;
}

static void sealed_remove(struct platform_device *pdev)
{
	sysfs_remove_bin_file(&pdev->dev.kobj, &sealed_attribute);
	kfree_sensitive(sealed_copy);
	sealed_copy = NULL;
	sealed_length = 0;
}

static const struct acpi_device_id sealed_ids[] = { { "GXFP51B7", 0 }, { } };
static struct platform_driver sealed_driver = {
	.probe = sealed_probe,
	.remove = sealed_remove,
	.driver = { .name = "gxfp51b7_sealed", .acpi_match_table = sealed_ids },
};
module_platform_driver(sealed_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Temporary root-only read of an encrypted GXFP51B7 BIOS SGX container");
