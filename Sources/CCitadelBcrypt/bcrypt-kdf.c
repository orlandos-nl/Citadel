#include <stdlib.h>
#include <string.h>

#ifndef __APPLE__
#include <sys/random.h>
#include <unistd.h>
#endif

#include "bcrypt-kdf.h"
#include "blf.h"

//#include "crypto_api.h"
#ifdef SHA512_DIGEST_LENGTH
# undef SHA512_DIGEST_LENGTH
#endif
#define SHA512_DIGEST_LENGTH 64

#define    MINIMUM(a,b) (((a) < (b)) ? (a) : (b))

/*
 * pkcs #5 pbkdf2 implementation using the "bcrypt" hash
 *
 * The bcrypt hash function is derived from the bcrypt password hashing
 * function with the following modifications:
 * 1. The input password and salt are preprocessed with SHA512.
 * 2. The output length is expanded to 256 bits.
 * 3. Subsequently the magic string to be encrypted is lengthened and modifed
 *    to "OxychromaticBlowfishSwatDynamite"
 * 4. The hash function is defined to perform 64 rounds of initial state
 *    expansion. (More rounds are performed by iterating the hash.)
 *
 * Note that this implementation pulls the SHA512 operations into the caller
 * as a performance optimization.
 *
 * One modification from official pbkdf2. Instead of outputting key material
 * linearly, we mix it. pbkdf2 has a known weakness where if one uses it to
 * generate (e.g.) 512 bits of key material for use as two 256 bit keys, an
 * attacker can merely run once through the outer loop, but the user
 * always runs it twice. Shuffling output bytes requires computing the
 * entirety of the key material to assemble any subkey. This is something a
 * wise caller could do; we just do it for you.
 */

#define BCRYPT_WORDS 8
#define BCRYPT_HASHSIZE (BCRYPT_WORDS * 4)

static void
bcrypt_hash(uint8_t *sha2pass, uint8_t *sha2salt, uint8_t *out)
{
    blf_ctx state;
    uint8_t ciphertext[BCRYPT_HASHSIZE] =
    "OxychromaticBlowfishSwatDynamite";
    uint32_t cdata[BCRYPT_WORDS];
    int i;
    uint16_t j;
    size_t shalen = SHA512_DIGEST_LENGTH;
    
    /* key expansion */
    citadel_Blowfish_initstate(&state);
    citadel_Blowfish_expandstate(&state, sha2salt, shalen, sha2pass, shalen);
    for (i = 0; i < 64; i++) {
        citadel_Blowfish_expand0state(&state, sha2salt, shalen);
        citadel_Blowfish_expand0state(&state, sha2pass, shalen);
    }
    
    /* encryption */
    j = 0;
    for (i = 0; i < BCRYPT_WORDS; i++)
            cdata[i] = citadel_Blowfish_stream2word(ciphertext, sizeof(ciphertext), &j);
    for (i = 0; i < 64; i++)
            citadel_blf_enc(&state, cdata, BCRYPT_WORDS / 2);
    
    /* copy out */
    for (i = 0; i < BCRYPT_WORDS; i++) {
        out[4 * i + 3] = (cdata[i] >> 24) & 0xff;
        out[4 * i + 2] = (cdata[i] >> 16) & 0xff;
        out[4 * i + 1] = (cdata[i] >> 8) & 0xff;
        out[4 * i + 0] = cdata[i] & 0xff;
    }
    
    /* zap */
    explicit_bzero(ciphertext, sizeof(ciphertext));
    explicit_bzero(cdata, sizeof(cdata));
    explicit_bzero(&state, sizeof(state));
}

int
citadel_bcrypt_pbkdf(const unsigned char *pass, size_t passlen, const uint8_t *salt, size_t saltlen,
                     uint8_t *key, size_t keylen, unsigned int rounds)
{
    uint8_t sha2pass[SHA512_DIGEST_LENGTH];
    uint8_t sha2salt[SHA512_DIGEST_LENGTH];
    uint8_t out[BCRYPT_HASHSIZE];
    uint8_t tmpout[BCRYPT_HASHSIZE];
    uint8_t *countsalt;
    size_t i, j, amt, stride;
    uint32_t count;
    size_t origkeylen = keylen;
    
    /* nothing crazy */
    if (rounds < 1)
        goto bad;
    if (passlen == 0 || saltlen == 0 || keylen == 0 ||
        keylen > sizeof(out) * sizeof(out) || saltlen > 1<<20)
        goto bad;
    if ((countsalt = calloc(1, saltlen + 4)) == NULL)
        goto bad;
    stride = (keylen + sizeof(out) - 1) / sizeof(out);
    amt = (keylen + stride - 1) / stride;
    
    memcpy(countsalt, salt, saltlen);
    
    /* collapse password */
    citadel_crypto_hash_sha512(sha2pass, pass, passlen);
    
    /* generate key, sizeof(out) at a time */
    for (count = 1; keylen > 0; count++) {
        countsalt[saltlen + 0] = (count >> 24) & 0xff;
        countsalt[saltlen + 1] = (count >> 16) & 0xff;
        countsalt[saltlen + 2] = (count >> 8) & 0xff;
        countsalt[saltlen + 3] = count & 0xff;
        
        /* first round, salt is salt */
        citadel_crypto_hash_sha512(sha2salt, countsalt, saltlen + 4);
        
        bcrypt_hash(sha2pass, sha2salt, tmpout);
        memcpy(out, tmpout, sizeof(out));
        
        for (i = 1; i < rounds; i++) {
            /* subsequent rounds, salt is previous output */
            citadel_crypto_hash_sha512(sha2salt, tmpout, sizeof(tmpout));
            bcrypt_hash(sha2pass, sha2salt, tmpout);
            for (j = 0; j < sizeof(out); j++)
                    out[j] ^= tmpout[j];
        }
        
        /*
         * pbkdf2 deviation: output the key material non-linearly.
         */
        amt = MINIMUM(amt, keylen);
        for (i = 0; i < amt; i++) {
            size_t dest = i * stride + (count - 1);
            if (dest >= origkeylen)
                break;
            key[dest] = out[i];
        }
        keylen -= i;
    }
    
    /* zap */
//    freezero(countsalt, saltlen + 4);
    free(countsalt);
    explicit_bzero(out, sizeof(out));
    explicit_bzero(tmpout, sizeof(tmpout));
    
    return 0;
    
bad:
    /* overwrite with random in case caller doesn't check return code */
#ifdef __APPLE__
    arc4random_buf(key, keylen);
#else
    getentropy(key, keylen);
#endif
    return -1;
}

void citadel_set_crypto_hash_sha512(void (*hash_fun)(unsigned char *out, const unsigned char *pass, unsigned long long passlen)) {
    citadel_crypto_hash_sha512 = hash_fun;
}
