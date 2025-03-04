#!/bin/bash
set -euo pipefail

if [ ! -d ../SEMLA ]; then
    echo "Cloning SEMLA to ../SEMLA"
    git clone https://github.com/modelica/Encryption-and-Licensing.git ../SEMLA
fi

# generate keys for testing
if [ ! -d ../openssl_keys ]; then
    echo "Generating keys for testing in ../openssl_keys"
    mkdir ../openssl_keys
    (
        cd ../openssl_keys
        openssl genrsa -out "private_key_tool.pem" 4096
        openssl genrsa -out "private_key_lve.pem" 4096
        openssl rsa -pubout -in "private_key_tool.pem" -out "public_key_tool.pem"
        echo public_key_tool.pem > public_key_tools.txt 
    )
fi
