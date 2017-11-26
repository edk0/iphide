#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "siphash.h"


static const uint8_t key[16] = {
	23, 29, 31, 37, 41, 43, 47, 53,
	59, 61, 67, 71, 73, 79, 83, 89,
};


static void addbit(void *in, void *out, size_t dstlen, size_t bit) {
	uint8_t hash[8];
	uint8_t *src = in  + bit / 8;
	uint8_t *dst = out + bit / 8;

	bit = 7 - bit % 8;

	*dst |= (1 << bit);
	siphash(out, dstlen, key, hash, sizeof hash);
	*dst &= ~(1 << bit);

	*dst |= ((*src >> bit & 1) ^ (hash[7] & 1)) << bit;
}


int main(int argc, char **argv) {
	char b[200];

	union {
		struct in_addr  ip4;
		struct in6_addr ip6;
	} addr, dst;

	memset(&dst, 0, sizeof dst);

	if (argc < 2) {
		fprintf(stderr, "%s <ip>\n", argv[0]);
		return -1;
	}

	if (!inet_pton(AF_INET, argv[1], &addr.ip4)) {
		fputs("invalid address", stderr);
		return -1;
	}

	for (int i = 0; i < 32; i++) {
		addbit(&addr.ip4, &dst.ip4, 4, i);
	}

	inet_ntop(AF_INET, &dst.ip4, b, sizeof b);
	puts(b);

	return 0;
}
