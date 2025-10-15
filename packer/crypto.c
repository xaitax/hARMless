#include "crypto.h"
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

void rc4_init(rc4_context_t* ctx, const uint8_t* key, size_t key_len) {
    int i, j;
    uint8_t temp;

    // Initialize S-box
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    j = 0;
    for (i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + key[i % key_len]) & 0xFF;
        temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    ctx->i = 0;
    ctx->j = 0;
}

void rc4_crypt(rc4_context_t* ctx, const uint8_t* input, uint8_t* output, size_t len) {
    size_t n;
    uint8_t temp;

    for (n = 0; n < len; n++) {
        ctx->i = (ctx->i + 1) & 0xFF;
        ctx->j = (ctx->j + ctx->S[ctx->i]) & 0xFF;

        temp = ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;

        output[n] = input[n] ^ ctx->S[(ctx->S[ctx->i] + ctx->S[ctx->j]) & 0xFF];
    }
}

void rc4_encrypt_decrypt(const uint8_t* key, size_t key_len, const uint8_t* input, uint8_t* output, size_t len) {
    rc4_context_t ctx;
    rc4_init(&ctx, key, key_len);
    rc4_crypt(&ctx, input, output, len);
}

// OpenSSL-based AES-256
void aes256_encrypt(uint8_t* data, size_t len, const uint8_t* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len;
    uint8_t* output = malloc(len + 16); // Padding space
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, output, &out_len, data, len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int final_len;
    EVP_EncryptFinal_ex(ctx, output + out_len, &final_len);

    memcpy(data, output, len); // Copy back (ECB mode preserves length)
    free(output);
    EVP_CIPHER_CTX_free(ctx);
}

void aes256_decrypt(uint8_t* data, size_t len, const uint8_t* key) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len;
    uint8_t* output = malloc(len + 16);
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_DecryptUpdate(ctx, output, &out_len, data, len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int final_len;
    EVP_DecryptFinal_ex(ctx, output + out_len, &final_len);

    memcpy(data, output, len);
    free(output);
    EVP_CIPHER_CTX_free(ctx);
}

// OpenSSL-based ChaCha20
void chacha20_encrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return;

    // ChaCha20 uses 32-byte key, 16-byte IV (nonce + counter)
    uint8_t iv[16] = {0};
    memcpy(iv, nonce, 12); // Copy 12-byte nonce, counter starts at 0

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    int out_len;
    uint8_t* output = malloc(len);
    if (!output) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    if (EVP_EncryptUpdate(ctx, output, &out_len, data, len) != 1) {
        free(output);
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    memcpy(data, output, len);
    free(output);
    EVP_CIPHER_CTX_free(ctx);
}

void chacha20_decrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    // ChaCha20 is symmetric
    chacha20_encrypt(data, len, key, nonce);
}
