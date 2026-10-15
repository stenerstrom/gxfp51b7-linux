#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "frame.h"
#include "chicago_config.h"

int main(void)
{
	unsigned char packet[265];
	memset(packet, 0xcc, sizeof(packet));
	assert(chicago_config_frame(packet, 263) == 0);
	assert(packet[0] == 0xcc);
	assert(chicago_config_frame(packet, 264) == 264);
	assert(packet[264] == 0xcc);
	assert(frame_valid(packet, 264));
	/* Independent known results from the verified original table and
	 * download_general_config checksum, not arbitrary synthetic settings. */
	assert(packet[4] == 0x90 && packet[5] == 1 && packet[6] == 1);
	assert(packet[7] == 0x70 && packet[8] == 0x11);
	assert(packet[261] == 0x93 && packet[262] == 0x0e);
	assert(packet[263] == 0x6f);
	packet[133] ^= 1;
	assert(!frame_valid(packet, 264));
	puts("Chicago type-12 fixed config framing, known checksums and buffer bounds passed");
	return 0;
}
