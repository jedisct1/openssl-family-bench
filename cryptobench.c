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
bench_run(const EVP_CIPHER *cipher, size_t total_size, size_t block_size)
{
    EVP_CIPHER_CTX *ctx;
    unsigned char   iv[12]  = { 0 };
    unsigned char   key[32] = { 0 };
    unsigned char   ad[13]  = { 0 };
    unsigned char  *buf;
    size_t          rounds = total_size / block_size;
    uint64_t        start, duration;
    unsigned int    i;
    int             len;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL);

    buf = calloc(block_size + 16, 1U);

    start = time_now();
    for (i = 0U; i < rounds; i++) {
        EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, iv);
        EVP_EncryptUpdate(ctx, NULL, &len, ad, (int) sizeof ad);
        EVP_EncryptUpdate(ctx, buf, &len, buf, (int) block_size);
        EVP_EncryptFinal_ex(ctx, buf, &len);
        __asm__ __volatile__("" : : "r"(buf) : "memory");
    }
    duration = time_now() - start;

    free(buf);
    EVP_CIPHER_CTX_free(ctx);

    return (uint64_t) (total_size * 8ULL * 1000000ULL) / (duration * 1024ULL * 1024ULL);
}

typedef struct Cipher {
    const char *name;
    const EVP_CIPHER *(*fn)();
} Cipher;

static const Cipher ciphers[] = {
    { "AES-128-GCM", EVP_aes_128_gcm },
    { "AES-256-GCM", EVP_aes_256_gcm },
    { "AES-128-CBC", EVP_aes_128_cbc },
    { "AES-256-CBC", EVP_aes_256_cbc },
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