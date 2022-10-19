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
bench_run(int nid, unsigned int rounds)
{
    EC_KEY *sk = EC_KEY_new_by_curve_name(nid);
    EC_KEY_generate_key(sk);

    const EC_POINT *pk         = EC_KEY_get0_public_key(sk);
    unsigned int    field_size = EC_GROUP_get_degree(EC_KEY_get0_group(sk));
    size_t          secret_len = (field_size + 7) / 8;
    uint8_t        *secret     = OPENSSL_malloc(secret_len);

    uint64_t start, duration;
    start = time_now();
    for (unsigned int i = 0U; i < rounds; i++) {
        ECDH_compute_key(secret, secret_len, pk, sk, NULL);
        __asm__ __volatile__("" : : "r"(secret) : "memory");
    }
    duration = time_now() - start;

    OPENSSL_free(secret);
    EC_KEY_free(sk);

    return (uint64_t) (rounds * 1000000ULL) / duration;
}

typedef struct Curve {
    const char *name;
    int         nid;
} Curve;

static const Curve curves[] = {
    { "p256", NID_X9_62_prime256v1 },
    { "p384", NID_secp384r1 },
};

int
main(void)
{
    for (size_t i = 0U; i < (sizeof curves) / (sizeof curves[0]); i++) {
        puts(curves[i].name);
        printf("%" PRIu64 "\n", bench_run(curves[i].nid, 100000));
        puts("\n--------\n");
    }
    return 0;
}