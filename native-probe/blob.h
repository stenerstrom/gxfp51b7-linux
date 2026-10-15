/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_BLOB_H
#define GXFP_BLOB_H

/* The original GetPSKFromDSMMethod uses a big-endian 32-bit outer length.
 * SGX structure offsets are checked against Intel's sgx_key.h/sgx_tseal.h.
 * Classification checks structure only; it cannot authenticate or decrypt it.
 */
struct blob_metadata {
	unsigned int container_len;
	unsigned int payload_len;
	unsigned int encrypted_len;
	unsigned int key_name;
	unsigned int key_policy;
};

static inline unsigned int blob_u32le(const unsigned char *p)
{
	return p[0] | ((unsigned int)p[1] << 8) |
		((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static inline int blob_zeros(const unsigned char *p, unsigned int n)
{
	unsigned int i;
	for (i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

/* 0 = invalid container, 1 = bounded container, 2 = consistent SGX structure. */
static inline int blob_parse_metadata(const unsigned char *p, unsigned int n,
				      struct blob_metadata *out)
{
	unsigned int size, payload, encrypted, name, policy;
	const unsigned char *sealed;
	if (!out)
		return 0;
	*out = (struct blob_metadata) { 0 };
	if (n < 4)
		return 0;
	size = ((unsigned int)p[0] << 24) | ((unsigned int)p[1] << 16) |
		((unsigned int)p[2] << 8) | p[3];
	if (!size || size > n - 4)
		return 0;
	out->container_len = size;
	if (size < 0x230)
		return 1;
	sealed = p + 4;
	name = sealed[0] | ((unsigned int)sealed[1] << 8);
	policy = sealed[2] | ((unsigned int)sealed[3] << 8);
	encrypted = blob_u32le(sealed + 0x200);
	payload = blob_u32le(sealed + 0x210);
	if (name != 4 || !policy || (policy & ~3U) ||
	    !payload || payload != size - 0x230 || encrypted > payload ||
	    !blob_zeros(sealed + 6, 2) || !blob_zeros(sealed + 78, 434) ||
	    !blob_zeros(sealed + 0x204, 12) || !blob_zeros(sealed + 0x214, 12))
		return 1;
	out->payload_len = payload;
	out->encrypted_len = encrypted;
	out->key_name = name;
	out->key_policy = policy;
	return 2;
}
#endif
