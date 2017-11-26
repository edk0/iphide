#include <stdint.h>
#include <stddef.h>

int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
            uint8_t *out, const size_t outlen);
int halfsiphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
                uint8_t *out, const size_t outlen);
