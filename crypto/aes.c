#ifndef USE_MBEDTLS

#include <openssl/evp.h>
#include <openssl/err.h>

#else

#include <mbedtls/aes.h>
#include <mbedtls/error.h>
//evp mbedtls replacement
#include "evp.h"

#endif


#include "pub/err.h"

#include "aes.h"

// encrypt if enc == 1
// decrypt if enc == 0
// the caller should allocate enough mem for output
ssize_t _crypto_evp_cipher(const EVP_CIPHER *evp,
                           const byte_t *key, const byte_t *iv,
                           const byte_t *data, size_t data_size,
                           byte_t *out, int enc)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len1, len2;

    // TRACE("%d", EVP_CIPHER_block_size(evp));

#define CLEAR_EXIT(code) \
    do { \
        int _c = (code); \
        if (_c == -1) { \
            ERR_print_errors_fp(stderr); \
        } \
        EVP_CIPHER_CTX_free(ctx); \
        return _c; \
    } while (0)

    if (!EVP_CipherInit(ctx, evp, key, iv, enc)) CLEAR_EXIT(-1);
    if (!EVP_CipherUpdate(ctx, out, &len1, data, data_size)) CLEAR_EXIT(-1);
    if (!EVP_CipherFinal(ctx, out + len1, &len2)) CLEAR_EXIT(-1);

    CLEAR_EXIT(len1 + len2);

#undef CLEAR_EXIT
}

byte_t *_crypto_aes(const EVP_CIPHER *type,
                    const byte_t *key, const byte_t *iv,
                    const byte_t *data, size_t data_size,
                    size_t *out_size_p, int enc)
{
    size_t out_size = data_size + EVP_CIPHER_block_size(type);
    byte_t *ret = malloc(out_size);

    ASSERT(ret, "malloc failed");

    out_size = _crypto_evp_cipher(type, key, iv, data, data_size, ret, enc);

    if (out_size == -1) return NULL;

    ret = realloc(ret, out_size);

    if (out_size_p)
        *out_size_p = out_size;

    return ret;
}

#define GEN_AES(mode, block_size) \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _enc \
        (const byte_t *key, const byte_t *iv, \
         const byte_t *data, size_t data_size, \
         size_t *out_size_p) \
    { \
        return _crypto_aes(EVP_aes_ ## block_size ## _ ## mode(), key, iv, data, data_size, out_size_p, 1); \
    } \
    \
    byte_t *crypto_aes_ ## block_size ## _ ## mode ## _dec \
        (const byte_t *key, const byte_t *iv, \
         const byte_t *ctext, size_t ctext_size, \
         size_t *out_size_p) \
    { \
        return _crypto_aes(EVP_aes_ ## block_size ## _ ## mode(), key, iv, ctext, ctext_size, out_size_p, 0); \
    }

GEN_AES(cfb, 128)
GEN_AES(cfb, 256)
// GEN_AES(gcm)
