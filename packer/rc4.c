#include "rc4.h"

void rc4_init(rc4_context_t* ctx, const uint8_t* key, size_t key_len) {
    int i, j;
    uint8_t temp;

    // Initialize S-box
    for (i = 0; i < 256; i++) {
        ctx->S[i] = i;
    }

    // Key scheduling algorithm (KSA)
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
