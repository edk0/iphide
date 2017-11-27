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

#define SKIP_PREFIX_V4 12
#define SKIP_PREFIX_V6 32

#define FEISTEL_ROUNDS 4


static uint8_t keys[FEISTEL_ROUNDS][16];


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


static void addbit_decrypt(void *in, void *out, size_t dstlen, size_t bit, void *scratch_) {
	uint8_t *scratch = scratch_;
	uint8_t hash[8];
	uint8_t *src = in  + bit / 8;
	uint8_t *dst = out + bit / 8;
	uint8_t *sd = scratch + bit / 8;

	bit = 7 - bit % 8;

	*sd |= (1 << bit);
	siphash(scratch, dstlen, key, hash, sizeof hash);
	if (!(*src >> bit & 1))
		*sd &= ~(1 << bit);

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


static void prepare_keys(void) {
	uint8_t ktmp[16];
	memcpy(keys[0], key, sizeof key);
	for (size_t i = 1; i < FEISTEL_ROUNDS; i++) {
		uint8_t *k = keys[i - 1];
		/* not a proper key schedule but i've decided it's good enough */
		for (int j = 0; j < 16; j+=2)
			ktmp[j] = k[j] ^ k[j+1], ktmp[j+1] = key[j+1];
		siphash(k, 16, ktmp, keys[i], sizeof keys[i]);
	}
}


static void permute(void *in, void *out, size_t bits, int reverse) {
	uint8_t bl[8] = {0}, br[8] = {0};
	uint8_t *l = bl, *r = br, *tmp;
	size_t ll = (bits - 1) / 2 + 1;
	size_t cut;
	uint8_t hash[8];

	if (reverse && FEISTEL_ROUNDS % 2 == 0) {
		ll = bits - ll;
	}
	bitcopy(bl, 0, in, 0, ll);
	bitcopy(br, 0, in, ll, bits - ll);

	for (int i = 0; i < FEISTEL_ROUNDS; i++) {
		const uint8_t *k = reverse ? keys[FEISTEL_ROUNDS - i - 1] : keys[i];
		/* number of bits to keep. bl is the original l */
		size_t cut = (l == bl) ? ll : bits - ll;
		siphash(r, 8, k, hash, sizeof hash);
		for (size_t j = 0; j < (cut - 1) / 8 + 1; j++)
			l[j] ^= hash[j];
		if (cut % 8)
			l[cut/8] &= 0xff << (8 - cut % 8);
		tmp = l; l = r; r = tmp;
	}

	tmp = l; l = r; r = tmp;
	cut = (l == bl) ? ll : bits - ll;

	bitcopy(out, 0, l, 0, cut);
	bitcopy(out, cut, r, 0, bits - cut);
}


int main(int argc, char **argv) {
	char b[200] = {0};
	int af;
	size_t start, end;
	int reverse;

	union {
		struct in_addr  ip4;
		struct in6_addr ip6;
	} addr, dst;

	prepare_keys();

	memset(&dst, 0, sizeof dst);

	if (argc < 2) {
		fprintf(stderr, "%s <ip>\n", argv[0]);
		return -1;
	}

	reverse = 0;
	if (*argv[1] == '?') {
		reverse = 1;
		argv[1]++;
	}

	if (inet_pton(AF_INET, argv[1], &addr.ip4)) {
		af = AF_INET;
	} else if (inet_pton(AF_INET6, argv[1], &addr.ip6)) {
		af = AF_INET6;
	} else {
		fputs("invalid address", stderr);
		return -1;
	}

	switch (af) {
	case AF_INET:
		permute(&addr.ip4, &dst.ip4, SKIP_PREFIX_V4, reverse);
		start = SKIP_PREFIX_V4;
		end = 32;
		break;
	case AF_INET6:
		permute(&addr.ip6, &dst.ip6, SKIP_PREFIX_V6, reverse);
		start = SKIP_PREFIX_V6;
		end = 128;
		break;
	default:
		fputs("error", stderr);
		return -1;
	}

	if (!reverse) {
		for (int i = start; i < end; i++)
			addbit(&addr, &dst, end / 8, i);
	} else {
		uint8_t scratch[8] = {0};
		bitcopy(scratch, 0, &addr, 0, start);
		for (int i = start; i < end; i++)
			addbit_decrypt(&addr, &dst, end / 8, i, scratch);
	}

	inet_ntop(af, &dst, b, sizeof b);
	printf("%s -> %s\n", argv[1], b);

	return 0;
}
