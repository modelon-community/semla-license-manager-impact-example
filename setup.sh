#!/bin/bash
set -euo pipefail

ARTIFACTS_URL=https://github.com/modelon-community/semla-license-manager-impact-example/releases/download/1.0.0-beta.1

SEMLA_OPENSSL_ZIP=SemlaOpenSSL-1.1.0-linux64-gcc485.zip
SEMLA_LIBJWT_ZIP=SemlaLibJWT-1.0.14-linux64-gcc485.zip
JANSSON_ZIP=jansson-1.0.4.zip
JWK2KEY=jwk2key

for ART in ${SEMLA_OPENSSL_ZIP} ${SEMLA_LIBJWT_ZIP} ${JANSSON_ZIP} ${JWK2KEY}
do
    if [ ! -f ${ART} ]; then
        echo Downloading ${ART}
        curl -LO ${ARTIFACTS_URL}/${ART}
    fi
done
chmod +x ${JWK2KEY}

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

if [ ! -f jwt_keys/public_keys_jwt.txt ]; then
    ./update_jwt_keys_from_wellknown.sh
fi

mkdir -p ve
if ! command -v cmake 2>&1 >/dev/null
then
    echo "cmake not found; setting up in a venv"
    if [ ! -d build/venv]; then
        echo Creating Python venv and installing cmake
        python -m venv build/venv
        . build/venv/bin/activate
        pip install cmake
    fi
fi

# if [ ! -f /usr/include/check.h ] ; then
#  TODO: disable check
# fi
