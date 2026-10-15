/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef GXFP_TLS_HELLO_H
#define GXFP_TLS_HELLO_H
#include "frame.h"

struct tls_hello_metadata {
	unsigned int record_version, client_version, cipher_bytes, extensions;
	unsigned int extended_master_secret, null_compression;
	const unsigned char *ciphers;
};

static inline unsigned int tls_u16be(const unsigned char *p)
{
	return ((unsigned int)p[0] << 8) | p[1];
}

/* A complete TLS record inside a Goodix B packet. This checks framing,
 * not authenticity: the first ClientHello is plaintext and has no MAC.
 * No random values, session identifiers or key material are exported.
 */
static inline int frame_tls_record(const unsigned char *p, unsigned int n)
{
	return n >= 9 && frame_length(p, n) == n && (p[0] & 0xf0) == 0xb0 &&
	       p[4] >= 20 && p[4] <= 23 && p[5] == 3 && p[6] <= 3 &&
	       tls_u16be(p + 7) == n - 9;
}

/* Bounded parser for one unfragmented TLS ClientHello. Reject unsupported
 * layouts rather than treating a generic ACK or partial record as proof.
 */
static inline int frame_tls_client_hello(const unsigned char *p, unsigned int n,
					 struct tls_hello_metadata *out)
{
	struct tls_hello_metadata m = { 0 };
	unsigned int at, len, end, i;
	if (!frame_tls_record(p, n) || n < 54 || p[4] != 22 || p[9] != 1 ||
	    (((unsigned int)p[10] << 16) | ((unsigned int)p[11] << 8) | p[12]) != n - 13)
		return 0;
	m.record_version = tls_u16be(p + 5);
	m.client_version = tls_u16be(p + 13);
	if (p[13] != 3 || p[14] < 1 || p[14] > 3 || p[47] > 32)
		return 0;
	at = 48 + p[47];
	if (at > n || n - at < 2)
		return 0;
	len = tls_u16be(p + at);
	at += 2;
	if (!len || (len & 1) || len > n - at)
		return 0;
	m.cipher_bytes = len;
	m.ciphers = p + at;
	at += len;
	if (at == n)
		return 0;
	len = p[at++];
	if (!len || len > n - at)
		return 0;
	for (i = 0; i < len; i++)
		m.null_compression |= p[at + i] == 0;
	at += len;
	if (at != n) {
		if (n - at < 2 || tls_u16be(p + at) != n - at - 2)
			return 0;
		at += 2;
		end = n;
		while (at < end) {
			unsigned int type;
			if (end - at < 4)
				return 0;
			type = tls_u16be(p + at);
			len = tls_u16be(p + at + 2);
			at += 4;
			if (len > end - at)
				return 0;
			if (type == 23) {
				if (len)
					return 0;
				m.extended_master_secret = 1;
			}
			m.extensions++;
			at += len;
		}
	}
	*out = m;
	return 1;
}
#endif
