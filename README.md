# ARM64 ELF Packer/Loader

A comprehensive ARM64 ELF packer and loader system for AArch64 Linux binaries. This tool encrypts ARM64 ELF executables using multi layer encryption and provides runtime in-memory execution without writing the original binary to disk.

## Features

- **ARM64 ELF Support**: Specifically designed for AArch64 Linux binaries
- **Multi Layer Encryption**: Encryption using AES256, chacha20 and rc4
- **Memory Execution**: Runtime decryption and execution entirely in memory
- **Code Obfuscation**: 
- **CRC32 Verification**: Integrity checking to detect tampering
- **Self-Contained**: Packed binaries are completely standalone

## Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd hARMless
```

### 3. Build All Components
```bash
make all
```

## Usage

### Packing a Binary
```bash
# Pack an ARM64 ELF binary
make pack INPUT=your_arm64_binary OUTPUT=packed_binary

# Or use the tools directly:
./build/packer your_arm64_binary packed_data
./build/stubgen ./build/loader packed_data packed_binary
```

### Running Packed Binaries
```bash
# On ARM64 systems, just run the packed binary:
./packed_binary

# The packed binary will:
# 1. Read its own packed data
# 2. Decrypt the original ELF
# 3. Verify integrity with CRC32
# 4. Execute in memory using memfd_create
```


## Security Features

- **Core Dump Prevention**: The loader disables core dumps at runtime using `setrlimit(RLIMIT_CORE, ...)`, ensuring that sensitive memory is never written to disk, even if the process crashes.
- **Secure Memory Wipe**: Sensitive data such as decrypted binaries and cryptographic keys are erased from memory using a multi-pass overwrite function. This function overwrites memory with zeros, ones, and random bytes to reduce the risk of data recovery from RAM.

## Technical Details

### Encryption
- **Algorithm**: RC4, AES256, CHACHA20
- **Key Size**: 256 bits (32 bytes)
- **Key Generation**: Random keys from `/dev/urandom`
- **Integrity**: CRC32 checksums for tamper detection

### ARM64 Syscalls
Direct syscall implementation for maximum compatibility:
- `memfd_create` (279) - Create anonymous file descriptor
- `execve` (221) - Execute binary
- `mmap` (222) - Memory mapping
- `write` (64) - Write data

### Features to implement
- Page encryption/decryption

## License

This project is licensed under the MIT License - see the LICENSE file for details.

