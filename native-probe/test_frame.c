#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "frame.h"

int main(void)
{
	unsigned char p[128] = { 0xa0, 9, 0, 0xa9, 0x82, 6, 0, 0, 0, 0, 4, 0, 0x1e };
	unsigned int i, j;
	const unsigned char chip_query[] = { 0xa0, 4, 0, 0xa4, 0x90, 1, 0, 0x19 };
	const unsigned char chip_reply[] = { 0xa0, 7, 0, 0xa7, 0xb0, 4, 0, 0x90, 0xe0, 0xe1, 0xa5 };
	unsigned char candidate[sizeof(chip_reply)];
	unsigned char ack_only[] = { 0xa0, 5, 0, 0xa5, 0xb0, 2, 0, 0x90, 0x68 };
	unsigned int chip_id = 0xdead;
	/* Original SetDriverState has two payload bytes, not a one-byte enable. */
	const unsigned char loaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 1, 0, 0x10 };
	const unsigned char unloaded[] = { 0xa0, 6, 0, 0xa6, 0x96, 3, 0, 0, 0, 0x11 };
	const unsigned char get_state[] = { 0xa0, 5, 0, 0xa5, 0xae, 2, 0, 0x55, 0xa5 };
	/* Live register data: 04 a2 00 25. Original pair swap gives a2 04 25 00. */
	const unsigned char register_reply[] = { 0xa0, 8, 0, 0xa8, 0x82, 5, 0, 4, 0xa2, 0, 0x25, 0x58 };
	unsigned char register_candidate[sizeof(register_reply)];
	const unsigned char get_pmk_hash[] = { 0xa0, 4, 0, 0xa4, 0xe4, 1, 0, 0xc5 };
	unsigned char hash_reply[49] = { 0xa0, 45, 0, 0xcd, 0xe4, 42, 0, 0 };
	const unsigned char *hash_data = NULL;
	unsigned int hash_status = 0xdead, hash_len = 0xdead, sum = 0;
	assert(frame_valid(loaded, sizeof(loaded)));
	assert(frame_valid(unloaded, sizeof(unloaded)));
	assert(frame_valid(get_state, sizeof(get_state)));
	assert(frame_valid(get_pmk_hash, sizeof(get_pmk_hash)));
	hash_reply[8] = 0x0d;
	hash_reply[12] = 32;
	for (i = 4; i < sizeof(hash_reply) - 1; i++) sum += hash_reply[i];
	hash_reply[48] = 0xaa - sum;
	assert(frame_pmk_hash_result(hash_reply, sizeof(hash_reply), &hash_status, &hash_data, &hash_len));
	assert(hash_status == 0 && hash_len == 40 && hash_data == hash_reply + 8);
	assert(frame_u32le(hash_data) == 0x0d && frame_u32le(hash_data + 4) == 32);
	for (i = 0; i < sizeof(hash_reply); i++)
		assert(!frame_pmk_hash_result(hash_reply, i, &hash_status, &hash_data, &hash_len));
	/* A checksummed frame for an unrelated operation is rejected. */
	hash_reply[4] = 0xe6; hash_reply[48] -= 2;
	assert(frame_valid(hash_reply, sizeof(hash_reply)));
	assert(!frame_pmk_hash_result(hash_reply, sizeof(hash_reply), &hash_status, &hash_data, &hash_len));
	assert(!frame_pmk_hash_result(get_pmk_hash, sizeof(get_pmk_hash), &hash_status, &hash_data, &hash_len));
	assert(!frame_pmk_hash_result(NULL, 0, &hash_status, &hash_data, &hash_len));
	assert(frame_register_chip_id(register_reply, sizeof(register_reply), &chip_id));
	assert(chip_id == 0x2504);
	assert(!frame_register_chip_id(NULL, 0, &chip_id));
	for (i = 0; i < sizeof(register_reply); i++) {
		chip_id = 0xdead;
		assert(!frame_register_chip_id(register_reply, i, &chip_id));
		assert(chip_id == 0xdead);
		for (j = 0; j < 8; j++) {
			memcpy(register_candidate, register_reply, sizeof(register_reply));
			register_candidate[i] ^= 1U << j;
			assert(!frame_register_chip_id(register_candidate, sizeof(register_candidate), &chip_id));
		}
	}

	/* Published transaction, truncation and single-bit corruption. */
	assert(frame_valid(chip_query, sizeof(chip_query)));
	assert(frame_chip_id(chip_reply, sizeof(chip_reply), &chip_id));
	assert(chip_id == 0xe1e0);
	assert(!frame_chip_id(NULL, 0, &chip_id));
	for (i = 0; i < sizeof(chip_reply); i++) {
		chip_id = 0xdead;
		assert(!frame_chip_id(chip_reply, i, &chip_id));
		assert(chip_id == 0xdead);
		for (j = 0; j < 8; j++) {
			memcpy(candidate, chip_reply, sizeof(candidate));
			candidate[i] ^= 1U << j;
			assert(!frame_chip_id(candidate, sizeof(candidate), &chip_id));
		}
	}
	/* A valid generic ACK must not be mistaken for a chip-ID result. */
	assert(frame_valid(ack_only, sizeof(ack_only)));
	assert(!frame_chip_id(ack_only, sizeof(ack_only), &chip_id));
	/* Valid frames with an unrelated message or echoed command also fail. */
	memcpy(candidate, chip_reply, sizeof(candidate));
	candidate[4] = 0x82; candidate[10] = 0xd3;
	assert(frame_valid(candidate, sizeof(candidate)));
	assert(!frame_chip_id(candidate, sizeof(candidate), &chip_id));
	memcpy(candidate, chip_reply, sizeof(candidate));
	candidate[7] = 0x82; candidate[10] = 0xb3;
	assert(frame_valid(candidate, sizeof(candidate)));
	assert(!frame_chip_id(candidate, sizeof(candidate), &chip_id));
	assert(frame_length(p, sizeof(p)) == 13);
	assert(frame_valid(p, 13));
	p[0] = 0xa1; p[3] = 0xaa;
	assert(frame_valid(p, 13));
	p[0] = 0xa0; p[3] = 0xa9;
	assert(!frame_valid(NULL, 0));
	for (i = 0; i < 8; i++) assert(!frame_valid(p, i));
	assert(!frame_valid(p, 12));
	p[12] ^= 1;
	assert(!frame_valid(p, 13));
	/* Exhaust all outer lengths, capacities including zero, and inner lengths. */
	for (i = 0; i <= 65535; i++) {
		p[1] = i; p[2] = i >> 8; p[3] = p[0] + p[1] + p[2];
		for (j = 0; j <= sizeof(p); j++) {
			unsigned int n = frame_length(p, j);
			assert(!n || (n <= j && n >= 8));
			if (n) (void)frame_valid(p, n);
		}
	}
	memset(p, 0, sizeof(p));
	p[0] = 0xa0; p[1] = 124; p[3] = p[0] + p[1];
	for (i = 0; i <= 65535; i++) {
		p[5] = i; p[6] = i >> 8;
		(void)frame_valid(p, sizeof(p));
	}
	puts("Frame bounds/checksum tests passed");
	return 0;
}
