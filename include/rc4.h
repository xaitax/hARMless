#ifndef RC4_H
#define RC4_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t S[256];
    uint8_t i;
    uint8_t j;
} rc4_context_t;

void rc4_init(rc4_context_t* ctx, const uint8_t* key, size_t key_len);
void rc4_crypt(rc4_context_t* ctx, const uint8_t* input, uint8_t* output, size_t len);

void rc4_encrypt_decrypt(const uint8_t* key, size_t key_len, const uint8_t* input, uint8_t* output, size_t len);

#endif // RC4_H
