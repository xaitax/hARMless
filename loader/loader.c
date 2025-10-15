#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <time.h>
#include <errno.h>
#include "common.h"
#include "elf64.h"
#include "rc4.h"

static const uint32_t crc32_table[256] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F,
    0xE963A535, 0x9E6495A3, 0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91, 0x1DB71064, 0x6AB020F2,
    0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9,
    0xFA0F3D63, 0x8D080DF5, 0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B, 0x35B5A8FA, 0x42B2986C,
    0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423,
    0xCFBA9599, 0xB8BDA50F, 0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D, 0x76DC4190, 0x01DB7106,
    0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D,
    0x91646C97, 0xE6635C01, 0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457, 0x65B0D9C6, 0x12B7E950,
    0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7,
    0xA4D1C46D, 0xD3D6F4FB, 0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9, 0x5005713C, 0x270241AA,
    0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81,
    0xB7BD5C3B, 0xC0BA6CAD, 0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683, 0xE3630B12, 0x94643B84,
    0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB,
    0x196C3671, 0x6E6B06E7, 0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5, 0xD6D6A3E8, 0xA1D1937E,
    0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55,
    0x316E8EEF, 0x4669BE79, 0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F, 0xC5BA3BBE, 0xB2BD0B28,
    0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F,
    0x72076785, 0x05005713, 0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21, 0x86D3D2D4, 0xF1D4E242,
    0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69,
    0x616BFFD3, 0x166CCF45, 0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB, 0xAED16A4A, 0xD9D65ADC,
    0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693,
    0x54DE5729, 0x23D967BF, 0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
};

uint32_t crc32(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    size_t i;
    for (i = 0; i < len; i++) {
        crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

int detect_ptrace_arm64(void) {
    pid_t child = fork();
    if (child == 0) { 
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            exit(1);
        }
        exit(0); 
    } else if (child > 0) {
        int status;
        waitpid(child, &status, 0);
        return WEXITSTATUS(status) != 0;
    }
    return 0;
}

int check_proc_status(void) {
    FILE* status_file = fopen("/proc/self/status", "r");
    if (!status_file) return 0;

    char line[256];
    while (fgets(line, sizeof(line), status_file)) {
        if (strncmp(line, "TracerPid:", 10) == 0) {
            int tracer_pid = atoi(line + 10);
            fclose(status_file);
            return tracer_pid != 0;
        }
    }
    fclose(status_file);
    return 0;
}

int check_parent_process(void) {
    FILE* stat_file = fopen("/proc/self/stat", "r");
    if (!stat_file) return 0;

    pid_t ppid;
    fscanf(stat_file, "%*d %*s %*c %d", &ppid);
    fclose(stat_file);

    char comm_path[64];
    snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", ppid);

    FILE* comm_file = fopen(comm_path, "r");
    if (comm_file) {
        char parent_name[64];
        if (fgets(parent_name, sizeof(parent_name), comm_file)) {
            fclose(comm_file);

            parent_name[strcspn(parent_name, "\n")] = 0;

            // Check for analysis tools
            if (strcmp(parent_name, "gdb") == 0 ||
                strcmp(parent_name, "strace") == 0 ||
                strcmp(parent_name, "ltrace") == 0 ||
                strcmp(parent_name, "radare2") == 0 ||
                strcmp(parent_name, "objdump") == 0 ||
                strcmp(parent_name, "hexdump") == 0 ||
                strcmp(parent_name, "ghidra") == 0) {
                return 1;
            }
        } else {
            fclose(comm_file);
        }
    }
    return 0;
}


int detect_virtualization(void) {
    FILE* cpuinfo = fopen("/proc/cpuinfo", "r");
    if (!cpuinfo) return 0;

    char line[256];
    while (fgets(line, sizeof(line), cpuinfo)) {
        for (char* p = line; *p; p++) {
            if (*p >= 'A' && *p <= 'Z') *p += 32;
        }

        if (strstr(line, "hypervisor") || strstr(line, "qemu") || 
            strstr(line, "kvm") || strstr(line, "xen") ||
            strstr(line, "vmware") || strstr(line, "virtualbox")) {
            fclose(cpuinfo);
            return 1;
        }
    }
    fclose(cpuinfo);

    // Check for virtualization-specific files and directories
    if (access("/proc/xen", F_OK) == 0) return 1;
    if (access("/sys/hypervisor/type", F_OK) == 0) return 1;
    if (access("/proc/vz", F_OK) == 0) return 1;
    if (access("/proc/bc", F_OK) == 0) return 1;

    return 0;
}

int check_debug_environment(void) {
    // Check suspicious environment variables
    if (getenv("LD_PRELOAD")) return 1;
    if (getenv("GDB")) return 1;
    if (getenv("PTRACE_SCOPE")) return 1;
    if (getenv("STRACE_LOG")) return 1;
    if (getenv("LTRACE_LOG")) return 1;
    if (getenv("RADARE2_LOG")) return 1;

    return 0;
}

int comprehensive_anti_debug_check() {

    // This logic can be expanded
    if (detect_ptrace_arm64()) {
        return 1;
    }
    if (check_proc_status()) {
        return 1;
    }
    if (check_parent_process()) {
        return 1;
    }
    if (detect_virtualization()) {
        return 1;
    }
    if (check_debug_environment()) {
        return 1;
    }

    return 0;
}


void multi_layer_decrypt(uint8_t* data, size_t len, const pack_header_t* header) {
    
    rc4_encrypt_decrypt(header->tertiary_key, 32, data, data, len);
    
    chacha20_decrypt(data, len, header->secondary_key, header->nonce);

    aes256_decrypt(data, len, header->primary_key);
    
}

pack_header_t* find_packed_header(const uint8_t* data, size_t data_size) {
    if (data_size < sizeof(pack_header_t)) {
        return NULL;
    }
    for (size_t i = data_size - sizeof(pack_header_t); i > 0; i--) {
        pack_header_t* header = (pack_header_t*)(data + i);
        if (header->magic == PACKED_MAGIC) {
            return header;
        }
    }
    return NULL;
}

int main(int argc, char* argv[], char* envp[]) {
    FILE* self_fp;
    uint8_t* self_data;
    size_t self_size;
    pack_header_t* header;
    uint8_t* encrypted_data;
    uint8_t* decrypted_data;
    uint32_t calculated_crc;

    prevent_core_dumps();
    hide_process_title(argc, argv);

    self_fp = fopen("/proc/self/exe", "rb");
    if (!self_fp) {
        return 1;
    }

    fseek(self_fp, 0, SEEK_END);
    self_size = ftell(self_fp);
    fseek(self_fp, 0, SEEK_SET);

    self_data = malloc(self_size);
    if (!self_data) {
        fclose(self_fp);
        return 1;
    }

    if (fread(self_data, 1, self_size, self_fp) != self_size) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        fclose(self_fp);
        return 1;
    }
    fclose(self_fp);

    header = find_packed_header(self_data, self_size);
    if (!header) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }

    if (comprehensive_anti_debug_check()) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        exit(0);
    }

    encrypted_data = (uint8_t*)header + sizeof(pack_header_t);
    if (encrypted_data + header->packed_size > self_data + self_size) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }
    decrypted_data = malloc(header->original_size);
    if (!decrypted_data) {
        secure_memory_wipe(self_data, self_size);
        free(self_data);
        return 1;
    }

    memcpy(decrypted_data, encrypted_data, header->original_size);

    multi_layer_decrypt(decrypted_data, header->original_size, header);
    calculated_crc = crc32(decrypted_data, header->original_size);
    if (calculated_crc != header->crc32) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }
    if (!is_elf64(decrypted_data)) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    } 
    if (comprehensive_anti_debug_check()) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        exit(0);
    }
    if (execute_from_memory(decrypted_data, header->original_size, argv, envp) < 0) {
        secure_memory_wipe(decrypted_data, header->original_size);
        secure_memory_wipe(self_data, self_size);
        free(decrypted_data);
        free(self_data);
        return 1;
    }

    secure_memory_wipe(decrypted_data, header->original_size);
    secure_memory_wipe(self_data, self_size);
    free(decrypted_data);
    free(self_data);

    return 0;
}