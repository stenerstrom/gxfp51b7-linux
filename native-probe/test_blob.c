#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "blob.h"
#include "../intel-sgx-sdk/common/inc/sgx_tseal.h"

int main(void)
{
	/* Verify constants against Intel's actual types, including old misleading
	 * decimal offset comments next to the 512-byte key_request member. */
	_Static_assert(sizeof(sgx_key_request_t) == 0x200, "SGX key request size");
	_Static_assert(offsetof(sgx_key_request_t, reserved2) == 78, "SGX padding");
	_Static_assert(offsetof(sgx_sealed_data_t, plain_text_offset) == 0x200, "SGX plaintext offset");
	_Static_assert(offsetof(sgx_sealed_data_t, aes_data) == 0x210, "SGX AES offset");
	_Static_assert(sizeof(sgx_sealed_data_t) == 0x230, "SGX fixed header size");
	unsigned char p[2048] = {0};
	struct blob_metadata m;
	unsigned int i;
	assert(!blob_parse_metadata(NULL, 0, &m));
	assert(!blob_parse_metadata(p, sizeof(p), NULL));
	/* Synthetic 885-byte SGX structure, never real key data. */
	p[2] = 3; p[3] = 0x75;
	p[4] = 4; p[6] = 2;
	p[4 + 0x200] = 0x45; p[4 + 0x201] = 1;
	p[4 + 0x210] = 0x45; p[4 + 0x211] = 1;
	assert(blob_parse_metadata(p, sizeof(p), &m) == 2);
	assert(m.container_len == 885 && m.payload_len == 325 && m.encrypted_len == 325);
	assert(m.key_name == 4 && m.key_policy == 2);
	for (i = 0; i < 889; i++)
		assert(!blob_parse_metadata(p, i, &m));
	/* Malformed or oversized structures cannot become a sealed-key claim. */
	p[4 + 0x200] = 0x46;
	assert(blob_parse_metadata(p, sizeof(p), &m) == 1);
	p[4 + 0x200] = 0x45;
	p[4 + 0x210] = 0x44;
	assert(blob_parse_metadata(p, sizeof(p), &m) == 1);
	p[4 + 0x210] = 0x45;
	p[4 + 78] = 1;
	assert(blob_parse_metadata(p, sizeof(p), &m) == 1);
	p[4 + 78] = 0;
	p[4] = 3;
	assert(blob_parse_metadata(p, sizeof(p), &m) == 1);
	memset(p, 0xff, sizeof(p));
	assert(!blob_parse_metadata(p, sizeof(p), &m));
	puts("BIOS container bounds and SGX layout tests passed");
	return 0;
}
