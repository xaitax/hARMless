# Compiler detection
UNAME_M := $(shell uname -m)
CC := gcc
TARGET_CC := gcc

# Cross-compilation setup for ARM64
ifeq ($(UNAME_M), x86_64)
    TARGET_CC := aarch64-linux-gnu-gcc
endif

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -std=c99
TARGET_CFLAGS := -Wall -Wextra -O2 -std=c99 -static
LDFLAGS := -static

# Security flags
SECURITY_FLAGS := -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE
STEALTH_FLAGS := -fomit-frame-pointer -s -fno-asynchronous-unwind-tables -fno-stack-protector

# Directories
INCLUDE_DIR := include
PACKER_DIR := packer
LOADER_DIR := loader
STUBGEN_DIR := stubgen
BUILD_DIR := build

# Output binaries
PACKER_BIN := $(BUILD_DIR)/packer
LOADER_BIN := $(BUILD_DIR)/loader
STUBGEN_BIN := $(BUILD_DIR)/stubgen

# Enhanced source files (including obfuscation)
PACKER_SOURCES := $(PACKER_DIR)/packer.c $(PACKER_DIR)/rc4.c $(PACKER_DIR)/obfuscation.c
LOADER_SOURCES := $(LOADER_DIR)/loader.c $(LOADER_DIR)/memexec.c $(PACKER_DIR)/elf64.c $(PACKER_DIR)/rc4.c $(PACKER_DIR)/obfuscation.c
STUBGEN_SOURCES := $(STUBGEN_DIR)/stubgen.c

# Include paths
INCLUDES := -I$(INCLUDE_DIR)

# Default target
all: $(BUILD_DIR) $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Build packer 
$(PACKER_BIN): $(PACKER_SOURCES)
	$(CC) $(CFLAGS) $(SECURITY_FLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Build loader
$(LOADER_BIN): $(LOADER_SOURCES)
	$(TARGET_CC) $(TARGET_CFLAGS) $(STEALTH_FLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Build stub generator 
$(STUBGEN_BIN): $(STUBGEN_SOURCES)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $^ $(LDFLAGS)

# Advanced packing presets
pack: $(PACKER_BIN) $(LOADER_BIN) $(STUBGEN_BIN)
	@if [ -z "$(INPUT)" ] || [ -z "$(OUTPUT)" ]; then \
		echo "Usage: make pack INPUT=<binary> OUTPUT=<output>"; \
		exit 1; \
	fi
	@echo "Creating maximum stealth packed binary..."
	$(PACKER_BIN) $(INPUT) $(OUTPUT).packed
	$(STUBGEN_BIN) $(LOADER_BIN) $(OUTPUT).packed $(OUTPUT)
	@echo "Output packed binary created: $(OUTPUT)"


# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -f *.packed
	rm -f test_* bench_*

# Install dependencies
install-deps:
	@echo "Installing ARM64 cross-compilation dependencies..."
	@if command -v apt-get >/dev/null 2>&1; then \
		sudo apt-get update && \
		sudo apt-get install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu; \
	elif command -v yum >/dev/null 2>&1; then \
		sudo yum install -y gcc-aarch64-linux-gnu binutils-aarch64-linux-gnu; \
	elif command -v pacman >/dev/null 2>&1; then \
		sudo pacman -S aarch64-linux-gnu-gcc aarch64-linux-gnu-binutils; \
	else \
		echo "Please install ARM64 cross-compilation tools manually"; \
	fi
