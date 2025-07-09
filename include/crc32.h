#ifndef CRC32_H
#define CRC32_H

#include <stdint.h>
#include <stddef.h>

// CRC32 function prototypes
uint32_t crc32(const uint8_t* data, size_t len);
uint32_t crc32_update(uint32_t crc, const uint8_t* data, size_t len);

#endif // CRC32_H
