#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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
bench_run(const EVP_AEAD *aead, size_t total_size, size_t block_size)
{
    EVP_AEAD_CTX   ctx;
    unsigned char  iv[12]  = { 0 };
    unsigned char  key[32] = { 0 };
    unsigned char  ad[13]  = { 0 };
    unsigned char *buf;
    size_t         rounds = total_size / block_size;
    uint64_t       start, duration;
    unsigned int   i;
    size_t         len;

    EVP_AEAD_CTX_init_with_direction(&ctx, aead, key, EVP_AEAD_key_length(aead),
                                     EVP_AEAD_DEFAULT_TAG_LENGTH, 1);
    buf = calloc(block_size + 16, 1U);

    start = time_now();
    for (i = 0U; i < rounds; i++) {
        EVP_AEAD_CTX_seal(&ctx, buf, &len, block_size + 16, iv, sizeof iv, buf, block_size, ad,
                          sizeof ad);
        __asm__ __volatile__("" : : "r"(buf) : "memory");
    }
    duration = time_now() - start;

    free(buf);

    return (uint64_t) (total_size * 8ULL * 1000000ULL) / (duration * 1024ULL * 1024ULL);
}

typedef struct Cipher {
    const char *name;
    const EVP_AEAD *(*fn)();
} Cipher;

static const Cipher ciphers[] = {
    { "AEGIS-128L", EVP_aead_aegis_128l },
    { "AES-128-GCM", EVP_aead_aes_128_gcm },
    { "AES-128-GCM-SIV", EVP_aead_aes_128_gcm_siv },
    { "CHACHA20-POLY1305", EVP_aead_chacha20_poly1305 },
};

int
main(void)
{
    const size_t total_size = 512 * 1024 * 1024ULL;
    size_t       block_size;
    size_t       i;

    for (i = 0U; i < (sizeof ciphers) / (sizeof ciphers[0]); i++) {
        puts(ciphers[i].name);
        puts("");

        puts("BlkSize\t MiB/s");
        block_size = 1;
        while (block_size <= 65536) {
            printf("%5zu\t%6" PRIu64 "\n", block_size,
                   bench_run(ciphers[i].fn(), total_size, block_size));
            block_size *= 2;
        }

        puts("\n--------\n");
    }
    return 0;
}