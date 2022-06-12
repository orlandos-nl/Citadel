#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>

int
citadel_bcrypt_pbkdf(const unsigned char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
                     uint8_t *key, size_t keylen, unsigned int rounds);

void (*citadel_crypto_hash_sha512)(unsigned char *out, const unsigned char *pass, unsigned long long passlen);

void citadel_set_crypto_hash_sha512(void (*hash_fun)(unsigned char *out, const unsigned char *pass, unsigned long long passlen));
