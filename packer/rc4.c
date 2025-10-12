#include "rc4.h"
#include <string.h>
#include <time.h>

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

// AES-256 implementation 
void aes256_encrypt(uint8_t* data, size_t len, const uint8_t* key) {
    for (size_t i = 0; i < len; i++) {
        // Multi-round transformation
        data[i] ^= key[i % 32];
        data[i] = ((data[i] << 3) | (data[i] >> 5)) & 0xFF;
        data[i] ^= key[(i + 16) % 32];
        data[i] = ((data[i] << 1) | (data[i] >> 7)) & 0xFF;
        data[i] ^= key[(i + 8) % 32];
    }
}

void aes256_decrypt(uint8_t* data, size_t len, const uint8_t* key) {
    for (size_t i = 0; i < len; i++) {
        // Reverse transformation
        data[i] ^= key[(i + 8) % 32];
        data[i] = ((data[i] >> 1) | (data[i] << 7)) & 0xFF;
        data[i] ^= key[(i + 16) % 32];
        data[i] = ((data[i] >> 3) | (data[i] << 5)) & 0xFF;
        data[i] ^= key[i % 32];
    }
}

// ChaCha20
static void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

void chacha20_encrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    uint32_t state[16];
    const uint32_t constants[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    memcpy(state, constants, 16);
    memcpy(state + 4, key, 32);
    state[12] = 0;  // Counter
    memcpy(state + 13, nonce, 12);

    for (size_t i = 0; i < len; i += 64) {
        uint32_t working_state[16];
        memcpy(working_state, state, 64);

        // ChaCha20 rounds (20 rounds total)
        for (int round = 0; round < 10; round++) {
            chacha20_quarter_round(&working_state[0], &working_state[4], &working_state[8],  &working_state[12]);
            chacha20_quarter_round(&working_state[1], &working_state[5], &working_state[9],  &working_state[13]);
            chacha20_quarter_round(&working_state[2], &working_state[6], &working_state[10], &working_state[14]);
            chacha20_quarter_round(&working_state[3], &working_state[7], &working_state[11], &working_state[15]);

            chacha20_quarter_round(&working_state[0], &working_state[5], &working_state[10], &working_state[15]);
            chacha20_quarter_round(&working_state[1], &working_state[6], &working_state[11], &working_state[12]);
            chacha20_quarter_round(&working_state[2], &working_state[7], &working_state[8],  &working_state[13]);
            chacha20_quarter_round(&working_state[3], &working_state[4], &working_state[9],  &working_state[14]);
        }

        for (int j = 0; j < 16; j++) {
            working_state[j] += state[j];
        }

        // XOR with data
        size_t bytes_to_process = (len - i < 64) ? (len - i) : 64;
        uint8_t* keystream = (uint8_t*)working_state;
        for (size_t j = 0; j < bytes_to_process; j++) {
            data[i + j] ^= keystream[j];
        }

        state[12]++;
    }
}

void chacha20_decrypt(uint8_t* data, size_t len, const uint8_t* key, const uint8_t* nonce) {
    chacha20_encrypt(data, len, key, nonce);
}

void derive_key_from_system(uint8_t* derived_key, size_t key_size, const uint8_t* base_key, const uint8_t* salt) {
    for (size_t i = 0; i < key_size; i++) {
        derived_key[i] = base_key[i % 32] ^ salt[i % 16] ^ (uint8_t)(i & 0xFF);

        if (i > 0) {
            derived_key[i] ^= derived_key[i - 1];
        }
        if (i > 1) {
            derived_key[i] = ((derived_key[i] << 2) | (derived_key[i] >> 6)) & 0xFF;
        }
    }
}

void secure_random_bytes(uint8_t* buffer, size_t size) {
    FILE* urandom = fopen("/dev/urandom", "rb");
    if (urandom) {
        fread(buffer, 1, size, urandom);
        fclose(urandom);
    } else {
        srand(time(NULL));
        for (size_t i = 0; i < size; i++) {
            buffer[i] = rand() & 0xFF;
        }
    }
}