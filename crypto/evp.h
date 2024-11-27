#ifndef MBEDTLS_COMPAT_H
#define MBEDTLS_COMPAT_H

#include <mbedtls/aes.h>
#include <mbedtls/md5.h>
#include <mbedtls/sha256.h>
#include <mbedtls/md.h>
#include <mbedtls/error.h>
#include <mbedtls/platform.h>
#include <mbedtls/cipher.h>
#include <string.h>

#define HMAC(md, key, key_len, data, data_len, out, out_len) ({ \
    int __hmac_ret = 0; \
    mbedtls_md_context_t __ctx; \
    const mbedtls_md_info_t *__info = md; \
    mbedtls_md_init(&__ctx); \
    if (__info && mbedtls_md_setup(&__ctx, __info, 1) == 0) { /* 1 = HMAC */ \
        if (mbedtls_md_hmac_reset(&__ctx) == 0 && \
            mbedtls_md_hmac_starts(&__ctx, (const unsigned char *)(key), (size_t)(key_len)) == 0 && \
            mbedtls_md_hmac_update(&__ctx, (const unsigned char *)(data), (size_t)(data_len)) == 0 && \
            mbedtls_md_hmac_finish(&__ctx, (unsigned char *)(out)) == 0) { \
            __hmac_ret = 1; /* Success */ \
        } \
    } \
    mbedtls_md_free(&__ctx); \
    __hmac_ret; \
})



// Replace OpenSSL MD5 functions
#define MD5(data, size, hash) (mbedtls_md5_ret((data), (size), (hash)) == 0)
#define EVP_MD mbedtls_md_info_t
#define EVP_md5() mbedtls_md_info_from_type(MBEDTLS_MD_MD5)

#define MD5_CTX mbedtls_md5_context
#define MD5_Init(ctx) mbedtls_md5_init(ctx)
#define MD5_Update(ctx, data, len) mbedtls_md5_ret(data, len, (unsigned char *)(ctx))
#define MD5_Final(out, ctx) memcpy(out, ctx, 16); mbedtls_md5_free(ctx)

// Replace OpenSSL HMAC functions
#define HMAC_CTX mbedtls_md_context_t
#define HMAC_CTX_new() (mbedtls_md_context_t *)calloc(1, sizeof(mbedtls_md_context_t))
#define HMAC_CTX_free(ctx) do { mbedtls_md_free(ctx); free(ctx); } while(0)
#define HMAC_Init_ex(ctx, key, key_len, md, impl) do { \
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(md); \
    mbedtls_md_init(ctx); \
    mbedtls_md_setup(ctx, info, 1); \
    mbedtls_md_hmac_starts(ctx, (const unsigned char *)(key), key_len); \
} while(0)
#define HMAC_Update(ctx, data, len) mbedtls_md_hmac_update(ctx, (const unsigned char *)(data), len)
#define HMAC_Final(ctx, out, len) mbedtls_md_hmac_finish(ctx, (unsigned char *)(out))

// Replace OpenSSL EVP Cipher functions
#define EVP_CIPHER_block_size(cipher) ((cipher)->block_size)

#define EVP_CIPHER_CTX mbedtls_cipher_context_t
#define EVP_CIPHER_CTX_new() (mbedtls_cipher_context_t *)calloc(1, sizeof(mbedtls_cipher_context_t))
#define EVP_CIPHER_CTX_free(ctx) do { mbedtls_cipher_free(ctx); free(ctx); } while(0)

#define EVP_EncryptInit_ex(ctx, cipher, impl, key, iv) do { \
    const mbedtls_cipher_info_t *cipher_info = mbedtls_cipher_info_from_type(cipher); \
    mbedtls_cipher_init(ctx); \
    mbedtls_cipher_setup(ctx, cipher_info); \
    mbedtls_cipher_setkey(ctx, (const unsigned char *)(key), cipher_info->key_bitlen, MBEDTLS_ENCRYPT); \
    if (cipher_info->iv_size > 0) { \
        mbedtls_cipher_set_iv(ctx, (const unsigned char *)(iv), cipher_info->iv_size); \
    } \
} while(0)

#define EVP_EncryptUpdate(ctx, out, outlen, in, inlen) do { \
    size_t out_len = 0; \
    mbedtls_cipher_update(ctx, (const unsigned char *)(in), inlen, (unsigned char *)(out), &out_len); \
    *(outlen) = (int)out_len; \
} while(0)

#define EVP_EncryptFinal_ex(ctx, out, outlen) do { \
    size_t out_len = 0; \
    mbedtls_cipher_finish(ctx, (unsigned char *)(out), &out_len); \
    *(outlen) = (int)out_len; \
} while(0)

// Replace OpenSSL error functions
#define ERR_load_crypto_strings() // No-op in mbedtls
#define ERR_print_errors_fp(fp) mbedtls_strerror(0, (char *)fp, 1024)

// Define macros to handle EVP_CIPHER and related functions
#define EVP_CIPHER const mbedtls_cipher_info_t

static inline int EVP_CipherInit(mbedtls_cipher_context_t *ctx, const mbedtls_cipher_info_t *cipher,
                                 const unsigned char *key, const unsigned char *iv, int enc) {
    int ret;

    mbedtls_cipher_init(ctx);
    ret = mbedtls_cipher_setup(ctx, cipher);
    if (ret != 0) {
        return ret;
    }

    ret = mbedtls_cipher_setkey(ctx, key, cipher->key_bitlen, enc ? MBEDTLS_ENCRYPT : MBEDTLS_DECRYPT);
    if (ret != 0) {
        return ret;
    }

    if (cipher->iv_size > 0) {
        ret = mbedtls_cipher_set_iv(ctx, iv, cipher->iv_size);
        if (ret != 0) {
            return ret;
        }
    }

    return 0; // Success
}

// Inline function for EVP_CipherUpdate equivalent
static inline int EVP_CipherUpdate(mbedtls_cipher_context_t *ctx, unsigned char *out,
                                   int *outlen, const unsigned char *in, int inlen) {
    size_t olen = 0;
    int ret = mbedtls_cipher_update(ctx, in, inlen, out, &olen);
    *outlen = (int)olen;
    return (ret == 0); // Return 1 for success, 0 for failure
}

// Inline function for EVP_CipherFinal equivalent
static inline int EVP_CipherFinal(mbedtls_cipher_context_t *ctx, unsigned char *out, int *outlen) {
    size_t olen = 0;
    int ret = mbedtls_cipher_finish(ctx, out, &olen);
    *outlen = (int)olen;
    return (ret == 0); // Return 1 for success, 0 for failure
}

#define EVP_aes_256_cbc() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC)
#define EVP_aes_128_cbc() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC)
#define EVP_aes_256_ecb() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_ECB)
#define EVP_aes_128_ecb() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB)
#define EVP_aes_128_cfb() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CFB128)
#define EVP_aes_256_cfb() mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CFB128)



#endif // MBEDTLS_COMPAT_H
