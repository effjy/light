#!/bin/bash

# create_test_file.sh – Generate a test file of given size (MiB)

echo "=== Test File Creator ==="

read -p "Enter file size in MB (e.g., 10): " size_mb
read -p "Enter output file name: " filename

if ! [[ "$size_mb" =~ ^[0-9]+$ ]]; then
    echo "Error: size must be a positive integer (megabytes)."
    exit 1
fi

if [ -z "$filename" ]; then
    echo "Error: filename cannot be empty."
    exit 1
fi

# Convert MB to bytes (1 MB = 1024*1024 bytes)
size_bytes=$((size_mb * 1024 * 1024))

echo "Creating $filename of size ${size_mb} MiB ($size_bytes bytes)..."

# Use dd with /dev/urandom for random data, show progress via status=progress
dd if=/dev/urandom of="$filename" bs=1M count="$size_mb" status=progress

if [ $? -eq 0 ]; then
    echo "File created: $filename ($(du -h "$filename" | cut -f1))"
else
    echo "Error creating file"
    exit 1
fi
