#!/bin/bash

# Simple unit test for hARMless
# Tests packing and execution of /bin/ls

set -e

echo "=== hARMless Test ==="
echo "Testing with /bin/ls"
echo

# Check if we're on ARM64
if [[ $(uname -m) != "aarch64" ]]; then
    echo "ERROR: This test must run on ARM64 architecture"
    exit 1
fi

# Check if /bin/ls exists and is ARM64 ELF
if [[ ! -f /bin/ls ]]; then
    echo "ERROR: /bin/ls not found"
    exit 1
fi

if ! file /bin/ls | grep -q "ARM aarch64"; then
    echo "ERROR: /bin/ls is not an ARM64 binary"
    exit 1
fi

echo
echo "[x] Found ARM64 /bin/ls"
echo

# Build the tools
echo "Building tools..."
cd ..
make clean && make all
cd tests

# Test packing
echo "Packing /bin/ls..."
../build/packer /bin/ls test_ls.packed

if [[ ! -f test_ls.packed ]]; then
    echo "ERROR: Packed file not created"
    exit 1
fi

echo
echo "[x] Created packed file: $(ls -lh test_ls.packed)"
echo

# Test stub generation
echo "Generating self-contained executable..."
../build/stubgen ../build/loader test_ls.packed test_ls_packed

if [[ ! -f test_ls_packed ]]; then
    echo "ERROR: Packed executable not created"
    exit 1
fi

echo
echo "[x] Created packed executable: $(ls -lh test_ls_packed)"
echo

chmod +x test_ls_packed

# Test execution
echo "Testing execution..."
timeout 10s ./test_ls_packed --version > /dev/null 2>&1
if [[ $? -eq 0 ]]; then
    echo
    echo "[x] Packed executable runs successfully"
    echo
else
    echo "ERROR: Packed executable failed to run"
    exit 1
fi

# Test that output is similar to original
echo "Comparing output with original..."
ORIGINAL_OUTPUT=$(timeout 5s /bin/ls --version 2>/dev/null | head -1 || echo "ls version output")
PACKED_OUTPUT=$(timeout 5s ./test_ls_packed --version 2>/dev/null | head -1 || echo "packed ls version output")

if [[ "$ORIGINAL_OUTPUT" == "$PACKED_OUTPUT" ]]; then
    echo
    echo "[x] Output matches original"
    echo
else
    echo "WARNING: Output differs from original"
    echo "  Original: $ORIGINAL_OUTPUT"
    echo "  Packed:   $PACKED_OUTPUT"
fi

# Test basic functionality
echo "Testing basic ls functionality..."
ORIGINAL_LS=$(timeout 5s /bin/ls / | wc -l)
PACKED_LS=$(timeout 5s ./test_ls_packed / | wc -l)

if [[ $ORIGINAL_LS -eq $PACKED_LS ]]; then
    echo
    echo "[x] Basic functionality works"
    echo
else
    echo "WARNING: Different output count ($ORIGINAL_LS vs $PACKED_LS)"
fi

# Cleanup
# echo "Cleaning up..."
# rm -f test_ls.packed test_ls_packed

echo
echo "[x] Test completed successfully."
