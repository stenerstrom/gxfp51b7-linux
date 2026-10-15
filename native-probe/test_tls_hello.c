#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "tls_hello.h"

static void lengths(unsigned char *p, unsigned int n)
{
	unsigned int body = n - 13;
	p[1] = n - 4; p[2] = (n - 4) >> 8; p[3] = p[0] + p[1] + p[2];
	p[7] = (n - 9) >> 8; p[8] = n - 9;
	p[10] = body >> 16; p[11] = body >> 8; p[12] = body;
}

int main(void)
{
	/* Synthetic TLS 1.2 ClientHello: zero-length session, two PSK suites,
	 * null compression, no extension vector. No captured personal data.
	 */
	unsigned char p[512] = { 0xb0, 0, 0, 0, 22, 3, 3, 0, 0, 1 };
	unsigned char copy[sizeof(p)];
	struct tls_hello_metadata m;
	unsigned int i, j, n = 56;
	p[13] = 3; p[14] = 3;
	p[48] = 0; p[49] = 4;
	p[50] = 0; p[51] = 0xa8; p[52] = 0; p[53] = 0xae;
	p[54] = 1; p[55] = 0;
	lengths(p, n);
	assert(frame_tls_record(p, n));
	assert(frame_tls_client_hello(p, n, &m));
	assert(m.client_version == 0x303 && m.record_version == 0x303);
	assert(m.cipher_bytes == 4 && tls_u16be(m.ciphers) == 0xa8);
	assert(tls_u16be(m.ciphers + 2) == 0xae);
	assert(m.null_compression == 1 && m.extensions == 0);
	assert(!frame_tls_client_hello(NULL, 0, &m));
	for (i = 0; i < n; i++) {
		assert(!frame_tls_client_hello(p, i, &m));
		for (j = 0; j < 8; j++) {
			memcpy(copy, p, sizeof(p)); copy[i] ^= 1U << j;
			(void)frame_tls_client_hello(copy, n, &m);
		}
	}
	memcpy(copy, p, sizeof(p)); copy[47] = 33;
	assert(!frame_tls_client_hello(copy, n, &m));
	memcpy(copy, p, sizeof(p)); copy[49] = 3;
	assert(!frame_tls_client_hello(copy, n, &m));
	memcpy(copy, p, sizeof(p)); copy[54] = 0;
	assert(!frame_tls_client_hello(copy, n, &m));
	/* Extended master secret is a zero-length extension, type 23. */
	p[56] = 0; p[57] = 4; p[58] = 0; p[59] = 23;
	n = 62; lengths(p, n);
	assert(frame_tls_client_hello(p, n, &m));
	assert(m.extensions == 1 && m.extended_master_secret == 1);
	for (i = 0; i <= 65535; i++) {
		p[60] = i >> 8; p[61] = i;
		assert(frame_tls_client_hello(p, n, &m) == (i == 0));
	}
	p[60] = 0; p[61] = 0;
	/* Wrong vector length and trailing partial extensions are rejected. */
	p[57] = 3; assert(!frame_tls_client_hello(p, n, &m)); p[57] = 4;
	for (i = 0; i <= sizeof(p); i++) {
		for (j = 0; j <= 65535; j += 257) {
			p[1] = j; p[2] = j >> 8; p[3] = p[0] + p[1] + p[2];
			(void)frame_tls_client_hello(p, i, &m);
		}
	}
	puts("TLS ClientHello bounds/structure tests passed");
	return 0;
}
