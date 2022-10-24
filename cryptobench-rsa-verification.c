#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef USE_WOLFSSL
#include <wolfssl/options.h>
#endif
#include <openssl/ssl.h>

#if defined(OPENSSL_WINDOWS)
#include <windows.h>
#elif defined(OPENSSL_APPLE)
#include <sys/time.h>
#else
#include <time.h>
#endif

#if defined(OPENSSL_WINDOWS)
static uint64_t
time_now()
{
    return GetTickCount64() * 1000;
}
#elif defined(OPENSSL_APPLE)
static uint64_t
time_now()
{
    struct timeval tv;
    uint64_t       ret;

    gettimeofday(&tv, NULL);
    ret = tv.tv_sec;
    ret *= 1000000;
    ret += tv.tv_usec;
    return ret;
}
#else
static uint64_t
time_now()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    uint64_t ret = ts.tv_sec;
    ret *= 1000000;
    ret += ts.tv_nsec / 1000;
    return ret;
}
#endif

static uint64_t
bench_run(int modulus_bits, unsigned int rounds)
{
    const int modulus_bytes = (modulus_bits + 7) / 8;

    RSA    *rsa = RSA_new();
    BIGNUM *e   = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, modulus_bits, e, NULL);
    EVP_PKEY *sk = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(sk, rsa);

    uint8_t  message[64] = { 0 };
    uint8_t *signature   = OPENSSL_malloc(modulus_bytes);

    RSA_private_encrypt(modulus_bytes, message, signature, (RSA *) EVP_PKEY_get0_RSA(sk),
                        RSA_NO_PADDING);

    uint64_t start, duration;
    start = time_now();
    for (unsigned int i = 0U; i < rounds; i++) {
        RSA_public_decrypt(modulus_bytes, signature, message, (RSA *) EVP_PKEY_get0_RSA(sk),
                           RSA_NO_PADDING);
        __asm__ __volatile__("" : : "r"(message) : "memory");
    }
    duration = time_now() - start;

    OPENSSL_free(signature);

    return (uint64_t) (rounds * 1000000ULL) / duration;
}

typedef struct ModulusBits {
    const char *name;
    int         modulus_bits;
} ModulusBits;

static const ModulusBits modulus_bits[] = {
    { "RSA 2048", 2048 },
    { "RSA 3072", 3072 },
};

int
main(void)
{
    for (size_t i = 0U; i < (sizeof modulus_bits) / (sizeof modulus_bits[0]); i++) {
        puts(modulus_bits[i].name);
        printf("%" PRIu64 "\n", bench_run(modulus_bits[i].modulus_bits, 10000));
        puts("\n--------\n");
    }
    return 0;
}