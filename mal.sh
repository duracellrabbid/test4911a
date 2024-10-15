#!/bin/bash

# Define URLs for the files
PYTHON_SCRIPT_URL="https://samplecontentsite.com/test.py"
BINARY_URL="https://samplecontentsite.com/program1"

# Download test.py using wget
echo "Downloading test.py..."
wget $PYTHON_SCRIPT_URL

# Download program1 (Linux x86_64 binary) using wget
echo "Downloading program1..."
wget $BINARY_URL

# Make program1 executable
echo "Making program1 executable..."
chmod +x program1

# Run the Python script (test.py)
echo "Running test.py..."
python3 test.py

# Run the Linux binary (program1)
echo "Running program1..."
./program1
