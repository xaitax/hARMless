#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "common.h"

int sys_memfd_create(const char* name, unsigned int flags) {
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
}

int execute_from_memory(const uint8_t* elf_data, size_t elf_size, char* const argv[], char* const envp[]) {
    int memfd;
    char memfd_path[256];

    memfd = sys_memfd_create("packed_elf", 0);
    if (memfd < 0) {
        fprintf(stderr, "Error: memfd_create failed: %s\n", strerror(errno));
        return -1;
    }
    if (sys_ftruncate(memfd, elf_size) < 0) {
        fprintf(stderr, "Error: ftruncate failed: %s\n", strerror(errno));
        close(memfd);
        return -1;
    }
    if (sys_write(memfd, elf_data, elf_size) != (ssize_t)elf_size) {
        fprintf(stderr, "Error: write failed: %s\n", strerror(errno));
        close(memfd);
        return -1;
    }

    snprintf(memfd_path, sizeof(memfd_path), "/proc/self/fd/%d", memfd);
    if (sys_execve(memfd_path, argv, envp) < 0) {
        fprintf(stderr, "Error: execve failed: %s\n", strerror(errno));
        close(memfd);
        return -1;
    }

    close(memfd);
    return 0;
}
