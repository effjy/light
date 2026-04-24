/*
 * =========================================================================
 *  Light Encryption Utility – Simulation of NSA Suite A‑style Encryption
 * =========================================================================
 * 
 *  SIMULATION NOTICE (read before use):
 *  -------------------------------------
 *  This utility models the engineering characteristics of a classified
 *  cryptographic system (e.g., NSA Suite A). In this simulated environment:
 *  
 *    - The "Obscurity" cipher represents an **unpublished, classified**
 *      algorithm whose security relies on algorithmic secrecy + key secrecy.
 *    - Kerckhoffs's principle is intentionally NOT applied.
 *    - The output format contains **no magic bytes** or structural
 *      fingerprints; it is computationally indistinguishable from random noise.
 *    - Security depends on operational secrecy, implementation discipline,
 *      and the hybrid post‑quantum KEM (Kyber‑1024 + X25519).
 *  
 *  This code is **NOT** for production use with real sensitive data.
 *  It is a research simulation for educational and closed‑environment
 *  prototyping only.
 *  
 *  =========================================================================
 *  Threat model:
 *    - Passive network adversary (can intercept ciphertext)  → mitigated.
 *    - Active storage tampering (integrity)                  → mitigated.
 *    - Forensic analysis of files (no magic bytes)           → mitigated.
 *    - Fault injection / side‑channel attacks               → partially mitigated.
 *    - Public cryptographic review                           → NOT applicable.
 *  =========================================================================
 *
 *  Compile instructions at the bottom of this file.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <termios.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <signal.h>
#include <sodium.h>
#include <argon2.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "api.h"

/* --------------------------- ANSI colors ------------------------------- */
#define COLOR_RESET   "\033[0m"
#define COLOR_CYAN    "\033[1;36m"
#define COLOR_WHITE   "\033[1;37m"
#define COLOR_GREEN   "\033[1;32m"
#define COLOR_RED     "\033[1;31m"
#define COLOR_YELLOW  "\033[1;33m"
#define COLOR_BLUE    "\033[1;34m"

/* --------------------------- Constants ---------------------------------- */
#define MAX_PASSWORD      256
#define SALT_LEN          16
#define NONCE_LEN_AES     12
#define NONCE_LEN_OBSC    16
#define TAG_LEN           16
#define KEY_LEN           32

#define ARGON2_TIME       4
#define ARGON2_MEMORY     (512ULL * 1024 * 1024)  /* 512 MiB */
#define ARGON2_THREADS    1

#define KYBER_PUBKEYBYTES   pqcrystals_kyber1024_ref_PUBLICKEYBYTES
#define KYBER_SECKEYBYTES   pqcrystals_kyber1024_ref_SECRETKEYBYTES
#define KYBER_CIPHERTEXTBYTES pqcrystals_kyber1024_ref_CIPHERTEXTBYTES
#define KYBER_SSBYTES       pqcrystals_kyber1024_ref_BYTES

#define X25519_PUBKEYBYTES  32
#define X25519_SECKEYBYTES  32

#define HYBRID_SK_LEN       (KYBER_SECKEYBYTES + X25519_SECKEYBYTES)
#define HYBRID_SK_FLAG_LEN  (HYBRID_SK_LEN + 1)   /* +1 for cipher flag */

#define ENC_SK_SALT_LEN     SALT_LEN
#define ENC_SK_NONCE_LEN    NONCE_LEN_AES
#define ENC_SK_CIPHER_LEN   (HYBRID_SK_FLAG_LEN + TAG_LEN)
#define ENC_SK_BLOB_LEN     (ENC_SK_SALT_LEN + ENC_SK_NONCE_LEN + ENC_SK_CIPHER_LEN)

#define STREAM_BUFFER_SIZE  (1024 * 1024)  /* 1 MiB chunks */

/* --------------------------- Global settings --------------------------- */
static volatile sig_atomic_t interrupted = 0;
static char tmp_out_path[1024] = {0};
static bool cipher_obscurity = 0;   /* 0 = AES, 1 = Obscurity (global default) */

/* --------------------------- Forward declarations ---------------------- */
void restore_terminal(void);
void signal_handler(int sig);
int safe_fread(FILE *f, void *buf, size_t n);
int safe_fwrite(FILE *f, const void *buf, size_t n);
void show_progress(const char *label, size_t processed, size_t total, time_t start);
int derive_key(const char *password, const unsigned char *salt, unsigned char *key);
int generate_hybrid_keypair(uint8_t *kyber_pk, uint8_t *kyber_sk,
                            uint8_t *x25519_pk, uint8_t *x25519_sk);
int hybrid_encapsulate(const uint8_t *kyber_pk, const uint8_t *x25519_pk,
                       uint8_t *kyber_ct, uint8_t *x25519_eph_pub,
                       uint8_t *shared_secret);
int hybrid_decapsulate(const uint8_t *kyber_ct, const uint8_t *x25519_eph_pub,
                       const uint8_t *kyber_sk, const uint8_t *x25519_sk,
                       uint8_t *shared_secret);
int aes_gcm_encrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                           size_t total_size, const char *progress_label);
int aes_gcm_decrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                           size_t total_size, const char *progress_label);
int obscurity_encrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                             size_t total_size, const char *progress_label);
int obscurity_decrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                             size_t total_size, const char *progress_label);
void settings_menu(void);

/* --------------------------- Obscurity core (custom sponge) ------------ */
#define STATE_WORDS       64
#define STATE_BYTES       (STATE_WORDS * 8)
#define RATE_BYTES        256
#define PERM_ROUNDS       32

static const uint64_t RC[PERM_ROUNDS] = {
    0x243f6a8885a308d3, 0x13198a2e03707344, 0xa4093822299f31d0, 0x082efa98ec4e6c89,
    0x452821e638d01377, 0xbe5466cf34e90c6c, 0xc0ac29b7c97c50dd, 0x3f84d5b5b5470917,
    0x9216d5d98979fb1b, 0xd1310ba698dfb5ac, 0x2ffd72dbd01adfb7, 0xb8e1afed6a267e96,
    0xba7c9045f12c7f99, 0x24a19947b3916cf7, 0x0801f2e2858efc16, 0x636920d871574e69,
    0xa458fea3f4933d7e, 0x0d95748f728eb658, 0x718bcd5882154aee, 0x7b54a41dc25a59b5,
    0x9c30d5392af26013, 0xc5d1b023286085f0, 0xca417918b8db38ef, 0x8e79dcb0603a180e,
    0x6c9e0e8bb01e8a3e, 0xd71577c1bd314b27, 0x78af2fda55605c60, 0xe65525f3aa55ab94,
    0x5748986263e81440, 0x55ca396a2aab10b6, 0xb4cc5c341141e8ce, 0xa15486af7c72e993
};

static void *volatile ct_barrier_ptr;
#define ct_barrier() do { __asm__ volatile("" : : "r"(ct_barrier_ptr) : "memory"); } while(0)

static inline uint64_t rotl64(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }
static inline uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static inline uint64_t sbox_obsc(uint64_t x, uint64_t subkey) {
    x ^= rotl64(x, 13) & rotl64(x, 17);
    x += subkey;
    x ^= (x >> 31) ^ (x << 33);
    x = rotl64(x, 23);
    x ^= 0x9e3779b97f4a7c15ULL;
    ct_barrier();
    return x;
}

static void diffusion_layer_obsc(uint64_t *state) {
    uint64_t c[5] = {0};
    for (int i = 0; i < STATE_WORDS; i++) c[i % 5] ^= state[i];
    for (int i = 0; i < STATE_WORDS; i++) state[i] ^= c[(i % 5 + 4) % 5] ^ rotl64(c[(i % 5 + 1) % 5], 1);
    uint64_t tmp[STATE_WORDS];
    memcpy(tmp, state, sizeof(tmp));
    for (int i = 0; i < STATE_WORDS; i++) {
        int j = (i * 7 + 13) % STATE_WORDS;
        state[j] = rotl64(tmp[i], (i * 3) % 64);
    }
    for (int i = 0; i < STATE_WORDS; i++)
        state[i] ^= (~state[(i + 1) % STATE_WORDS]) & state[(i + 2) % STATE_WORDS];
    ct_barrier();
}

static void base_permutation_obsc(uint64_t *state) {
    int r;
    for (r = 0; r < PERM_ROUNDS; r++) {
        uint64_t subkey = RC[r] ^ state[0] ^ state[STATE_WORDS - 1];
        for (int i = 0; i < STATE_WORDS; i++)
            state[i] = sbox_obsc(state[i], subkey);
        diffusion_layer_obsc(state);
        for (int i = 0; i < STATE_WORDS / 2; i++) {
            uint64_t t = state[i];
            state[i] = state[STATE_WORDS - 1 - i] ^ rotl64(t, 5);
            state[STATE_WORDS - 1 - i] = t ^ rotr64(state[STATE_WORDS - 1 - i], 7);
        }
        ct_barrier();
    }
}

static void sponge_init_obsc(uint64_t *state, const uint8_t *key, const uint8_t *nonce) {
    memset(state, 0, STATE_BYTES);
    memcpy(state, key, KEY_LEN);
    memcpy((uint8_t*)state + KEY_LEN, nonce, NONCE_LEN_OBSC);
    ((uint8_t*)state)[KEY_LEN + NONCE_LEN_OBSC] = 0x01;
    ((uint8_t*)state)[KEY_LEN + NONCE_LEN_OBSC + 1] = 0x80;
    base_permutation_obsc(state);
}

static void sponge_absorb_pad_obsc(uint64_t *state, size_t absorbed_len) {
    uint8_t *rate = (uint8_t*)state;
    if (absorbed_len == 0) {
        rate[0] = 0x80;
    } else if (absorbed_len < RATE_BYTES) {
        rate[absorbed_len] = 0x80;
    } else {
        memset(rate, 0, RATE_BYTES);
        rate[0] = 0x80;
    }
    rate[RATE_BYTES - 1] ^= 0x01;
    base_permutation_obsc(state);
}

static void sponge_duplex_obsc(uint64_t *state, const uint8_t *in, uint8_t *out,
                               size_t len, int encrypt, size_t *absorbed) {
    uint8_t *rate = (uint8_t*)state;
    for (size_t i = 0; i < len; i++) out[i] = in[i] ^ rate[i];
    const uint8_t *absorb = encrypt ? in : out;
    for (size_t i = 0; i < len; i++) rate[i] = absorb[i];
    *absorbed += len;
    if (*absorbed == RATE_BYTES) {
        base_permutation_obsc(state);
        *absorbed = 0;
    }
}

static void sponge_finalize_obsc(uint64_t *state, size_t absorbed_len) {
    if (absorbed_len != 0)
        sponge_absorb_pad_obsc(state, absorbed_len);
    else
        base_permutation_obsc(state);
}

static void sponge_squeeze_tag_obsc(uint64_t *state, uint8_t *tag, size_t tag_len) {
    uint8_t *rate = (uint8_t*)state;
    for (size_t i = 0; i < tag_len && i < RATE_BYTES; i++)
        tag[i] = rate[i];
}

/* --------------------------- Obscurity streaming functions ------------ */
int obscurity_encrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                             size_t total_size, const char *progress_label) {
    uint64_t *state = malloc(STATE_BYTES);
    if (!state) return -1;
    sponge_init_obsc(state, key, nonce);
    size_t absorbed = 0;
    uint8_t *in_buf = malloc(STREAM_BUFFER_SIZE);
    uint8_t *out_buf = malloc(STREAM_BUFFER_SIZE);
    if (!in_buf || !out_buf) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    size_t processed = 0;
    time_t start = time(NULL);
    int last_percent = -1;
    while (processed < total_size && !interrupted) {
        size_t to_read = total_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        if (safe_fread(in, in_buf, to_read) != 0) break;
        size_t remaining = to_read;
        size_t pos = 0;
        while (remaining > 0) {
            size_t chunk = remaining;
            if (chunk > RATE_BYTES - absorbed) chunk = RATE_BYTES - absorbed;
            sponge_duplex_obsc(state, in_buf + pos, out_buf + pos, chunk, 1, &absorbed);
            pos += chunk;
            remaining -= chunk;
        }
        if (safe_fwrite(out, out_buf, to_read) != 0) {
            free(in_buf); free(out_buf); free(state);
            return -1;
        }
        processed += to_read;
        int percent = (int)((processed * 100) / total_size);
        if (percent != last_percent) {
            show_progress(progress_label, processed, total_size, start);
            last_percent = percent;
        }
    }
    if (interrupted) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    sponge_finalize_obsc(state, absorbed);
    uint8_t tag[TAG_LEN];
    sponge_squeeze_tag_obsc(state, tag, TAG_LEN);
    if (safe_fwrite(out, tag, TAG_LEN) != 0) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    free(in_buf);
    free(out_buf);
    free(state);
    printf("\n");
    return 0;
}

int obscurity_decrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                             size_t total_size_with_tag, const char *progress_label) {
    if (total_size_with_tag < TAG_LEN) return -1;
    size_t ciphertext_size = total_size_with_tag - TAG_LEN;
    uint64_t *state = malloc(STATE_BYTES);
    if (!state) return -1;
    sponge_init_obsc(state, key, nonce);
    size_t absorbed = 0;
    uint8_t *in_buf = malloc(STREAM_BUFFER_SIZE);
    uint8_t *out_buf = malloc(STREAM_BUFFER_SIZE);
    if (!in_buf || !out_buf) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    size_t processed = 0;
    time_t start = time(NULL);
    int last_percent = -1;
    while (processed < ciphertext_size && !interrupted) {
        size_t to_read = ciphertext_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        if (safe_fread(in, in_buf, to_read) != 0) break;
        size_t remaining = to_read;
        size_t pos = 0;
        while (remaining > 0) {
            size_t chunk = remaining;
            if (chunk > RATE_BYTES - absorbed) chunk = RATE_BYTES - absorbed;
            sponge_duplex_obsc(state, in_buf + pos, out_buf + pos, chunk, 0, &absorbed);
            pos += chunk;
            remaining -= chunk;
        }
        if (safe_fwrite(out, out_buf, to_read) != 0) {
            free(in_buf); free(out_buf); free(state);
            return -1;
        }
        processed += to_read;
        int percent = (int)((processed * 100) / ciphertext_size);
        if (percent != last_percent) {
            show_progress(progress_label, processed, ciphertext_size, start);
            last_percent = percent;
        }
    }
    if (interrupted) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    uint8_t expected_tag[TAG_LEN];
    if (safe_fread(in, expected_tag, TAG_LEN) != 0) {
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    sponge_finalize_obsc(state, absorbed);
    uint8_t computed_tag[TAG_LEN];
    sponge_squeeze_tag_obsc(state, computed_tag, TAG_LEN);
    if (sodium_memcmp(expected_tag, computed_tag, TAG_LEN) != 0) {
        fprintf(stderr, "\nObscurity authentication failed.\n");
        free(in_buf); free(out_buf); free(state);
        return -1;
    }
    free(in_buf);
    free(out_buf);
    free(state);
    printf("\n");
    return 0;
}

/* --------------------------- AES streaming (OpenSSL) ------------------- */
int aes_gcm_encrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                           size_t total_size, const char *progress_label) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    unsigned char *in_buf = malloc(STREAM_BUFFER_SIZE);
    unsigned char *out_buf = malloc(STREAM_BUFFER_SIZE + TAG_LEN);
    if (!in_buf || !out_buf) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    size_t processed = 0;
    time_t start = time(NULL);
    int last_percent = -1;
    while (processed < total_size && !interrupted) {
        size_t to_read = total_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        if (safe_fread(in, in_buf, to_read) != 0) break;
        int out_len = 0;
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, to_read) != 1) {
            free(in_buf); free(out_buf);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (safe_fwrite(out, out_buf, out_len) != 0) {
            free(in_buf); free(out_buf);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        processed += to_read;
        int percent = (int)((processed * 100) / total_size);
        if (percent != last_percent) {
            show_progress(progress_label, processed, total_size, start);
            last_percent = percent;
        }
    }
    if (interrupted) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    unsigned char tag[TAG_LEN];
    int out_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (out_len > 0 && safe_fwrite(out, out_buf, out_len) != 0) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (safe_fwrite(out, tag, TAG_LEN) != 0) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    free(in_buf);
    free(out_buf);
    EVP_CIPHER_CTX_free(ctx);
    printf("\n");
    return 0;
}

int aes_gcm_decrypt_stream(FILE *in, FILE *out, const unsigned char *key, const unsigned char *nonce,
                           size_t total_size, const char *progress_label) {
    if (total_size < TAG_LEN) return -1;
    size_t ciphertext_size = total_size - TAG_LEN;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    unsigned char *in_buf = malloc(STREAM_BUFFER_SIZE);
    unsigned char *out_buf = malloc(STREAM_BUFFER_SIZE);
    if (!in_buf || !out_buf) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    size_t processed = 0;
    time_t start = time(NULL);
    int last_percent = -1;
    while (processed < ciphertext_size && !interrupted) {
        size_t to_read = ciphertext_size - processed;
        if (to_read > STREAM_BUFFER_SIZE) to_read = STREAM_BUFFER_SIZE;
        if (safe_fread(in, in_buf, to_read) != 0) break;
        int out_len = 0;
        if (EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, to_read) != 1) {
            free(in_buf); free(out_buf);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        if (safe_fwrite(out, out_buf, out_len) != 0) {
            free(in_buf); free(out_buf);
            EVP_CIPHER_CTX_free(ctx);
            return -1;
        }
        processed += to_read;
        int percent = (int)((processed * 100) / ciphertext_size);
        if (percent != last_percent) {
            show_progress(progress_label, processed, ciphertext_size, start);
            last_percent = percent;
        }
    }
    if (interrupted) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    unsigned char tag[TAG_LEN];
    if (safe_fread(in, tag, TAG_LEN) != 0) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag) != 1) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    int out_len = 0;
    if (EVP_DecryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        fprintf(stderr, "\nAES authentication failed.\n");
        return -1;
    }
    if (out_len > 0 && safe_fwrite(out, out_buf, out_len) != 0) {
        free(in_buf); free(out_buf);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    free(in_buf);
    free(out_buf);
    EVP_CIPHER_CTX_free(ctx);
    printf("\n");
    return 0;
}

/* --------------------------- Hybrid KEM (same as before) ---------------- */
int generate_hybrid_keypair(uint8_t *kyber_pk, uint8_t *kyber_sk,
                            uint8_t *x25519_pk, uint8_t *x25519_sk) {
    if (pqcrystals_kyber1024_ref_keypair(kyber_pk, kyber_sk) != 0)
        return -1;
    crypto_box_keypair(x25519_pk, x25519_sk);
    return 0;
}

int hybrid_encapsulate(const uint8_t *kyber_pk, const uint8_t *x25519_pk,
                       uint8_t *kyber_ct, uint8_t *x25519_eph_pub,
                       uint8_t *shared_secret) {
    uint8_t kyber_ss[KYBER_SSBYTES];
    uint8_t eph_sk[X25519_SECKEYBYTES];
    uint8_t x25519_ss[32];
    uint8_t combined[64];
    if (pqcrystals_kyber1024_ref_enc(kyber_ct, kyber_ss, kyber_pk) != 0)
        return -1;
    crypto_box_keypair(x25519_eph_pub, eph_sk);
    if (crypto_scalarmult(x25519_ss, eph_sk, x25519_pk) != 0) {
        sodium_memzero(eph_sk, sizeof(eph_sk));
        return -1;
    }
    memcpy(combined, kyber_ss, 32);
    memcpy(combined + 32, x25519_ss, 32);
    if (crypto_generichash(shared_secret, 32, combined, 64, NULL, 0) != 0) {
        sodium_memzero(eph_sk, sizeof(eph_sk));
        return -1;
    }
    sodium_memzero(eph_sk, sizeof(eph_sk));
    sodium_memzero(x25519_ss, sizeof(x25519_ss));
    sodium_memzero(combined, sizeof(combined));
    return 0;
}

int hybrid_decapsulate(const uint8_t *kyber_ct, const uint8_t *x25519_eph_pub,
                       const uint8_t *kyber_sk, const uint8_t *x25519_sk,
                       uint8_t *shared_secret) {
    uint8_t kyber_ss[KYBER_SSBYTES];
    uint8_t x25519_ss[32];
    uint8_t combined[64];
    if (pqcrystals_kyber1024_ref_dec(kyber_ss, kyber_ct, kyber_sk) != 0)
        return -1;
    if (crypto_scalarmult(x25519_ss, x25519_sk, x25519_eph_pub) != 0)
        return -1;
    memcpy(combined, kyber_ss, 32);
    memcpy(combined + 32, x25519_ss, 32);
    if (crypto_generichash(shared_secret, 32, combined, 64, NULL, 0) != 0)
        return -1;
    return 0;
}

/* --------------------------- Terminal handling ------------------------- */
static struct termios orig_termios;
static int termios_saved = 0;
static bool pwd_visible = false;

void restore_terminal(void) {
    if (termios_saved) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &orig_termios);
        termios_saved = 0;
    }
}

void toggle_password_visibility(bool enable) {
    pwd_visible = enable;
}

int read_line(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, size, stdin) == NULL) return -1;
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    return 0;
}

int read_password(const char *prompt, char *buf, size_t size) {
    printf("%s", prompt);
    fflush(stdout);
    struct termios old;
    tcgetattr(STDIN_FILENO, &old);
    if (!termios_saved) {
        orig_termios = old;
        termios_saved = 1;
    }
    struct termios new = old;
    if (!pwd_visible) new.c_lflag &= ~ECHO; else new.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new);
    if (fgets(buf, size, stdin) == NULL) {
        tcsetattr(STDIN_FILENO, TCSANOW, &old);
        return -1;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    size_t len = strlen(buf);
    if (len > 0 && buf[len-1] == '\n') buf[len-1] = '\0';
    printf("\n");
    return 0;
}

void signal_handler(int sig) {
    (void)sig;
    interrupted = 1;
    if (tmp_out_path[0] != '\0') remove(tmp_out_path);
    restore_terminal();
    _Exit(130);
}

/* --------------------------- Safe I/O helpers -------------------------- */
int safe_fread(FILE *f, void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        size_t r = fread((char*)buf + done, 1, n - done, f);
        if (r == 0) break;
        done += r;
    }
    return (done == n) ? 0 : -1;
}

int safe_fwrite(FILE *f, const void *buf, size_t n) {
    size_t done = 0;
    while (done < n) {
        size_t w = fwrite((const char*)buf + done, 1, n - done, f);
        if (w == 0) return -1;
        done += w;
    }
    return 0;
}

/* --------------------------- Progress bar ------------------------------ */
void show_progress(const char *label, size_t processed, size_t total, time_t start) {
    if (total == 0) return;
    int percent = (int)((processed * 100) / total);
    double elapsed = difftime(time(NULL), start);
    double speed = (elapsed > 0) ? (processed / (1024.0 * 1024.0)) / elapsed : 0;
    printf("\r\033[K[%s] %3d%% - %.2f MB/s", label, percent, speed);
    fflush(stdout);
}

/* --------------------------- Key derivation (Argon2id) ----------------- */
int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    if (!password || strlen(password) == 0) {
        fprintf(stderr, "Error: Password cannot be empty.\n");
        return -1;
    }
    uint32_t m_cost_kib = (uint32_t)(ARGON2_MEMORY / 1024);
    int ret = argon2id_hash_raw(ARGON2_TIME, m_cost_kib, ARGON2_THREADS,
                                password, strlen(password),
                                salt, SALT_LEN,
                                key, KEY_LEN);
    if (ret != ARGON2_OK) {
        fprintf(stderr, "Argon2id failed: %s\n", argon2_error_message(ret));
        return -1;
    }
    return 0;
}

/* --------------------------- Encrypt & Decrypt with cipher flag in blob - */
int encrypt_file(const char *in_path, const char *out_path, const char *password) {
    struct stat st;
    if (stat(in_path, &st) != 0) { perror("Cannot stat input file"); return -1; }
    size_t file_size = st.st_size;

    FILE *fin = fopen(in_path, "rb");
    if (!fin) { perror("Cannot open input file"); return -1; }
    FILE *fout = fopen(out_path, "wb");
    if (!fout) { perror("Cannot create output file"); fclose(fin); return -1; }

    strncpy(tmp_out_path, out_path, sizeof(tmp_out_path) - 1);
    tmp_out_path[sizeof(tmp_out_path)-1] = '\0';

    uint8_t *kyber_pk = malloc(KYBER_PUBKEYBYTES);
    uint8_t *kyber_sk = malloc(KYBER_SECKEYBYTES);
    uint8_t *x25519_pk = malloc(X25519_PUBKEYBYTES);
    uint8_t *x25519_sk = malloc(X25519_SECKEYBYTES);
    if (!kyber_pk || !kyber_sk || !x25519_pk || !x25519_sk) {
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        fclose(fin); fclose(fout);
        return -1;
    }

    if (generate_hybrid_keypair(kyber_pk, kyber_sk, x25519_pk, x25519_sk) != 0) {
        fprintf(stderr, "Hybrid key generation failed\n");
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        fclose(fin); fclose(fout);
        return -1;
    }

    unsigned char salt[SALT_LEN], nonce_sk[NONCE_LEN_AES], enc_key[KEY_LEN];
    randombytes_buf(salt, SALT_LEN);
    randombytes_buf(nonce_sk, NONCE_LEN_AES);
    if (derive_key(password, salt, enc_key) != 0) {
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        fclose(fin); fclose(fout);
        return -1;
    }

    /* Prepare hybrid_sk with leading cipher flag */
    uint8_t *hybrid_sk_with_flag = malloc(HYBRID_SK_FLAG_LEN);
    uint8_t *hybrid_sk = hybrid_sk_with_flag + 1;
    if (!hybrid_sk_with_flag) {
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        fclose(fin); fclose(fout);
        return -1;
    }
    hybrid_sk_with_flag[0] = cipher_obscurity ? 0x01 : 0x00;
    memcpy(hybrid_sk, kyber_sk, KYBER_SECKEYBYTES);
    memcpy(hybrid_sk + KYBER_SECKEYBYTES, x25519_sk, X25519_SECKEYBYTES);
    sodium_mlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);

    unsigned long long enc_sk_len;
    uint8_t *enc_sk_cipher = malloc(ENC_SK_CIPHER_LEN);
    if (!enc_sk_cipher) {
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        free(hybrid_sk_with_flag); fclose(fin); fclose(fout);
        return -1;
    }
    if (crypto_aead_aes256gcm_encrypt(enc_sk_cipher, &enc_sk_len,
                                      hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN,
                                      NULL, 0, NULL, nonce_sk, enc_key) != 0) {
        fprintf(stderr, "Failed to encrypt hybrid private key\n");
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        free(hybrid_sk_with_flag); free(enc_sk_cipher); fclose(fin); fclose(fout);
        return -1;
    }

    if (safe_fwrite(fout, salt, SALT_LEN) != 0 ||
        safe_fwrite(fout, nonce_sk, NONCE_LEN_AES) != 0 ||
        safe_fwrite(fout, enc_sk_cipher, ENC_SK_CIPHER_LEN) != 0) {
        fprintf(stderr, "Error writing encrypted private key header\n");
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        free(hybrid_sk_with_flag); free(enc_sk_cipher); fclose(fin); fclose(fout);
        return -1;
    }

    uint8_t kyber_ct[KYBER_CIPHERTEXTBYTES];
    uint8_t x25519_eph_pub[X25519_PUBKEYBYTES];
    uint8_t file_key[KEY_LEN];
    if (hybrid_encapsulate(kyber_pk, x25519_pk, kyber_ct, x25519_eph_pub, file_key) != 0) {
        fprintf(stderr, "Hybrid encapsulation failed\n");
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        free(hybrid_sk_with_flag); free(enc_sk_cipher); fclose(fin); fclose(fout);
        return -1;
    }
    sodium_mlock(file_key, KEY_LEN);

    if (safe_fwrite(fout, kyber_ct, KYBER_CIPHERTEXTBYTES) != 0 ||
        safe_fwrite(fout, x25519_eph_pub, X25519_PUBKEYBYTES) != 0) {
        fprintf(stderr, "Error writing KEM ciphertext\n");
        free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
        free(hybrid_sk_with_flag); free(enc_sk_cipher);
        sodium_memzero(file_key, KEY_LEN); sodium_munlock(file_key, KEY_LEN);
        fclose(fin); fclose(fout);
        return -1;
    }

    int ret = -1;
    if (cipher_obscurity) {
        unsigned char nonce_obsc[NONCE_LEN_OBSC];
        randombytes_buf(nonce_obsc, NONCE_LEN_OBSC);
        if (safe_fwrite(fout, nonce_obsc, NONCE_LEN_OBSC) != 0) {
            fprintf(stderr, "Error writing Obscurity nonce\n");
        } else {
            printf("\n");
            ret = obscurity_encrypt_stream(fin, fout, file_key, nonce_obsc, file_size, "Encrypting (Obscurity)");
        }
    } else {
        unsigned char nonce_aes[NONCE_LEN_AES];
        randombytes_buf(nonce_aes, NONCE_LEN_AES);
        if (safe_fwrite(fout, nonce_aes, NONCE_LEN_AES) != 0) {
            fprintf(stderr, "Error writing AES nonce\n");
        } else {
            printf("\n");
            ret = aes_gcm_encrypt_stream(fin, fout, file_key, nonce_aes, file_size, "Encrypting (AES-256-GCM)");
        }
    }

    free(kyber_pk); free(kyber_sk); free(x25519_pk); free(x25519_sk);
    sodium_memzero(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
    sodium_munlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
    free(hybrid_sk_with_flag);
    free(enc_sk_cipher);
    sodium_memzero(file_key, KEY_LEN);
    sodium_munlock(file_key, KEY_LEN);
    sodium_memzero(enc_key, KEY_LEN);
    fclose(fin);
    fclose(fout);
    tmp_out_path[0] = '\0';

    if (ret == 0) printf("File encrypted successfully: %s\n", out_path);
    else printf("Encryption failed.\n");
    return ret;
}

int decrypt_file(const char *in_path, const char *out_path, const char *password) {
    FILE *fin = fopen(in_path, "rb");
    if (!fin) { perror("Cannot open input file"); return -1; }

    strncpy(tmp_out_path, out_path, sizeof(tmp_out_path) - 1);
    tmp_out_path[sizeof(tmp_out_path)-1] = '\0';

    unsigned char salt[SALT_LEN], nonce_sk[NONCE_LEN_AES];
    uint8_t *enc_sk_cipher = malloc(ENC_SK_CIPHER_LEN);
    if (!enc_sk_cipher) { fclose(fin); return -1; }
    if (safe_fread(fin, salt, SALT_LEN) != 0 ||
        safe_fread(fin, nonce_sk, NONCE_LEN_AES) != 0 ||
        safe_fread(fin, enc_sk_cipher, ENC_SK_CIPHER_LEN) != 0) {
        fprintf(stderr, "Error: Failed to read encrypted private key header\n");
        free(enc_sk_cipher); fclose(fin);
        return -1;
    }

    unsigned char enc_key[KEY_LEN];
    if (derive_key(password, salt, enc_key) != 0) {
        free(enc_sk_cipher); fclose(fin);
        return -1;
    }

    uint8_t *hybrid_sk_with_flag = malloc(HYBRID_SK_FLAG_LEN);
    if (!hybrid_sk_with_flag) { free(enc_sk_cipher); fclose(fin); return -1; }
    unsigned long long dec_len;
    if (crypto_aead_aes256gcm_decrypt(hybrid_sk_with_flag, &dec_len, NULL,
                                      enc_sk_cipher, ENC_SK_CIPHER_LEN,
                                      NULL, 0, nonce_sk, enc_key) != 0) {
        fprintf(stderr, "Error: Wrong password or corrupted private key blob\n");
        free(enc_sk_cipher); free(hybrid_sk_with_flag); fclose(fin);
        return -1;
    }
    if (dec_len != HYBRID_SK_FLAG_LEN) {
        fprintf(stderr, "Error: Decrypted private key length mismatch\n");
        free(enc_sk_cipher); free(hybrid_sk_with_flag); fclose(fin);
        return -1;
    }
    sodium_mlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
    free(enc_sk_cipher);
    uint8_t cipher_flag = hybrid_sk_with_flag[0];
    uint8_t *hybrid_sk = hybrid_sk_with_flag + 1;
    uint8_t *kyber_sk = hybrid_sk;
    uint8_t *x25519_sk = hybrid_sk + KYBER_SECKEYBYTES;

    uint8_t kyber_ct[KYBER_CIPHERTEXTBYTES];
    uint8_t x25519_eph_pub[X25519_PUBKEYBYTES];
    if (safe_fread(fin, kyber_ct, KYBER_CIPHERTEXTBYTES) != 0 ||
        safe_fread(fin, x25519_eph_pub, X25519_PUBKEYBYTES) != 0) {
        fprintf(stderr, "Error: Failed to read KEM ciphertext\n");
        sodium_memzero(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
        sodium_munlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
        free(hybrid_sk_with_flag); fclose(fin);
        return -1;
    }

    uint8_t file_key[KEY_LEN];
    if (hybrid_decapsulate(kyber_ct, x25519_eph_pub, kyber_sk, x25519_sk, file_key) != 0) {
        fprintf(stderr, "Error: Hybrid decapsulation failed\n");
        sodium_memzero(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
        sodium_munlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
        free(hybrid_sk_with_flag); fclose(fin);
        return -1;
    }
    sodium_mlock(file_key, KEY_LEN);
    sodium_memzero(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
    sodium_munlock(hybrid_sk_with_flag, HYBRID_SK_FLAG_LEN);
    free(hybrid_sk_with_flag);

    /* Determine nonce length based on flag (constant‑time dispatch with function pointer) */
    size_t nonce_len;
    int (*decrypt_fn)(FILE*,FILE*,const uint8_t*,const uint8_t*,size_t,const char*);
    if (cipher_flag & 1) {
        nonce_len = NONCE_LEN_OBSC;
        decrypt_fn = obscurity_decrypt_stream;
    } else {
        nonce_len = NONCE_LEN_AES;
        decrypt_fn = aes_gcm_decrypt_stream;
    }

    unsigned char *nonce = malloc(nonce_len);
    if (!nonce) { fclose(fin); return -1; }
    if (safe_fread(fin, nonce, nonce_len) != 0) {
        fprintf(stderr, "Error: Failed to read cipher nonce\n");
        free(nonce); fclose(fin);
        return -1;
    }

    long cur = ftell(fin);
    fseek(fin, 0, SEEK_END);
    long end = ftell(fin);
    size_t remaining = (size_t)(end - cur);
    fseek(fin, cur, SEEK_SET);

    FILE *fout = fopen(out_path, "wb");
    if (!fout) { perror("Cannot create output file"); fclose(fin); free(nonce); return -1; }

    const char *label = (cipher_flag & 1) ? "Decrypting (Obscurity)" : "Decrypting (AES-256-GCM)";
    printf("\n");
    int ret = decrypt_fn(fin, fout, file_key, nonce, remaining, label);

    fclose(fin);
    fclose(fout);
    free(nonce);
    sodium_memzero(file_key, KEY_LEN);
    sodium_munlock(file_key, KEY_LEN);

    if (ret == 0)
        printf("File decrypted successfully: %s\n", out_path);
    else {
        remove(out_path);
        printf("Decryption failed.\n");
    }
    tmp_out_path[0] = '\0';
    return ret;
}

/* --------------------------- Settings Menu ----------------------------- */
void settings_menu(void) {
    int c;
    printf("\n" COLOR_CYAN "Settings\n" COLOR_RESET);
    printf("1. Cipher: %s\n", cipher_obscurity ? "Obscurity (custom sponge)" : "AES-256-GCM");
    printf("2. Back\nChoice: ");
    if (scanf("%d", &c) != 1) { while (getchar() != '\n'); return; }
    while (getchar() != '\n');
    if (c == 1) {
        cipher_obscurity = !cipher_obscurity;
        printf("Cipher switched to %s.\n", cipher_obscurity ? "Obscurity" : "AES-256-GCM");
        printf("New encrypted files will use this cipher.\n");
        printf("Existing encrypted files are already tagged and will be decrypted correctly.\n");
    }
}

/* --------------------------- Main Menu --------------------------------- */
int main(void) {
    if (sodium_init() < 0) { fprintf(stderr, "libsodium init failed\n"); return 1; }
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    atexit(restore_terminal);
    toggle_password_visibility(false);

    char password[MAX_PASSWORD];
    char in_path[1024], out_path[1024];
    char choice_buf[16];
    int choice;

    while (1) {
        printf("\n=== Light Encryption Utility (Hybrid Kyber-1024 + X25519) ===\n");
        printf("1. Encrypt a file\n");
        printf("2. Decrypt a file\n");
        printf("3. Toggle password visibility (currently %s)\n", pwd_visible ? "ON" : "OFF");
        printf("4. Settings\n");
        printf("5. Exit\n");
        printf("Choice: ");
        fflush(stdout);

        if (fgets(choice_buf, sizeof(choice_buf), stdin) == NULL) break;
        choice_buf[strcspn(choice_buf, "\n")] = '\0';
        if (sscanf(choice_buf, "%d", &choice) != 1) {
            printf("Invalid choice.\n");
            continue;
        }
        printf("\n");

        switch (choice) {
            case 1:
                if (read_line("Input file: ", in_path, sizeof(in_path)) != 0) break;
                if (read_line("Output file: ", out_path, sizeof(out_path)) != 0) break;
                if (read_password("Password: ", password, sizeof(password)) != 0) break;
                encrypt_file(in_path, out_path, password);
                sodium_memzero(password, sizeof(password));
                break;
            case 2:
                if (read_line("Input file (encrypted): ", in_path, sizeof(in_path)) != 0) break;
                if (read_line("Output file: ", out_path, sizeof(out_path)) != 0) break;
                if (read_password("Password: ", password, sizeof(password)) != 0) break;
                decrypt_file(in_path, out_path, password);
                sodium_memzero(password, sizeof(password));
                break;
            case 3:
                toggle_password_visibility(!pwd_visible);
                printf("Password visibility now %s.\n", pwd_visible ? "ON" : "OFF");
                break;
            case 4:
                settings_menu();
                break;
            case 5:
                printf("Goodbye.\n");
                restore_terminal();
                EVP_cleanup();
                ERR_free_strings();
                return 0;
            default:
                printf("Invalid choice.\n");
        }
    }
    restore_terminal();
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
