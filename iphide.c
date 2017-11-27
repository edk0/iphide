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

#define SKIP_PREFIX 12

#define FEISTEL_ROUNDS 4


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


static void bitcopy(void *dst_, size_t dstbit, void *src_, size_t srcbit, size_t n)
{
#	define READ_BITS(nb_) do {\
		size_t nb = (nb_); \
		size_t p = nb < 8 - srcbit ? nb : 8 - srcbit; \
		c = src[0] << (srcbit); \
		if (p < nb) c |= (src[1] & 0xff << (8 - nb + p)) >> p; \
	} while (0)

	uint8_t c;
	uint8_t *dst = dst_, *src = src_;

	dst += dstbit / 8;
	dstbit = dstbit % 8;
	src += srcbit / 8;
	srcbit = srcbit % 8;

	/* set dst[dstbit..] from src */
	if (dstbit) {
		READ_BITS(8 - dstbit);
		*dst |= c >> dstbit;
		++dst;
		n -= 8 - dstbit;
		srcbit += 8 - dstbit;
		if (srcbit >= 8) {
			srcbit -= 8;
			src++;
		}
		dstbit = 0;
	}

	/* set dst from src */
	while (n >= 8) {
		READ_BITS(8);
		*dst++ = c;
		src++;
		n -= 8;
	}

	/* trail */
	if (n) {
		READ_BITS(n);
		*dst |= c;
	}
#	undef READ_BITS
}


static void permute(void *in, void *out, size_t bits) {
	uint8_t k[16], ktmp[16], khash[16];
	uint8_t bl[8] = {0}, br[8] = {0};
	uint8_t *l = bl, *r = br, *tmp;
	uint8_t hash[8];

	memcpy(k, key, sizeof k);

	bitcopy(bl, 0, in, 0, (bits - 1) / 2 + 1);
	bitcopy(br, 0, in, (bits - 1) / 2 + 1, bits / 2);

	for (int i = 0; i < FEISTEL_ROUNDS; i++) {
		/* number of bits to keep. bl is the original l */
		size_t trim = (l == bl) ? (bits - 1) / 2 + 1 : bits / 2;
		siphash(r, 8, key, hash, sizeof hash);
		for (size_t j = 0; j < (trim - 1) / 8 + 1; j++)
			l[j] ^= hash[j];
		if (trim % 8)
			l[trim/8] &= 0xff << (8 - trim % 8);
		tmp = l; l = r; r = tmp;
		/* not a proper key schedule but i've decided it's good enough */
		for (int j = 0; j < 16; j+=2)
			ktmp[j] = k[j] ^ k[j+1], ktmp[j+1] = key[j+1];
		siphash(k, 16, ktmp, khash, sizeof hash);
		memcpy(k, khash, sizeof k);
	}

	bitcopy(out, 0, bl, 0, (bits - 1) / 2 + 1);
	bitcopy(out, (bits - 1) / 2 + 1, br, 0, bits / 2);
}


int main(int argc, char **argv) {
	char b[200] = {0};

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

	permute(&addr.ip4, &dst.ip4, SKIP_PREFIX);
	for (int i = SKIP_PREFIX; i < 32; i++) {
		addbit(&addr.ip4, &dst.ip4, 4, i);
	}

	inet_ntop(AF_INET, &dst.ip4, b, sizeof b);
	printf("%s -> %s\n", argv[1], b);

	return 0;
}
