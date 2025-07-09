#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>

// Magic number for packed binaries
#define PACKED_MAGIC 0x50414B45  // "PAKE"

// Maximum key size for RC4
#define MAX_KEY_SIZE 256

// Pack header structure
typedef struct {
    uint32_t magic;
    uint32_t original_size;
    uint32_t packed_size;
    uint32_t crc32;
    uint32_t key_size;
    uint8_t key[MAX_KEY_SIZE];
} __attribute__((packed)) pack_header_t;

// Function prototypes
uint32_t crc32(const uint8_t* data, size_t len);
void generate_random_key(uint8_t* key, size_t key_size);

// ARM64 syscall numbers
#define __NR_read 63
#define __NR_write 64
#define __NR_open 56
#define __NR_close 57
#define __NR_mmap 222
#define __NR_munmap 215
#define __NR_execve 221
#define __NR_memfd_create 279
#define __NR_ftruncate 46
#define __NR_lseek 62

// ARM64 syscall wrapper
static inline long syscall1(long number, long arg1) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1)
        : "x0", "x8", "memory"
    );
    return ret;
}

static inline long syscall2(long number, long arg1, long arg2) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2)
        : "x0", "x1", "x8", "memory"
    );
    return ret;
}

static inline long syscall3(long number, long arg1, long arg2, long arg3) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2), "r"(arg3)
        : "x0", "x1", "x2", "x8", "memory"
    );
    return ret;
}

static inline long syscall6(long number, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6) {
    long ret;
    __asm__ volatile (
        "mov x8, %1\n"
        "mov x0, %2\n"
        "mov x1, %3\n"
        "mov x2, %4\n"
        "mov x3, %5\n"
        "mov x4, %6\n"
        "mov x5, %7\n"
        "svc 0\n"
        "mov %0, x0\n"
        : "=r"(ret)
        : "r"(number), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4), "r"(arg5), "r"(arg6)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8", "memory"
    );
    return ret;
}

#endif // COMMON_H
