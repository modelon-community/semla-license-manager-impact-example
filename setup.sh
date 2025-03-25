#!/bin/bash
# Copyright (C) 2022 Modelon AB
set -euo pipefail

SCRIPTFILE=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPTDIR=$(dirname "$SCRIPTFILE")
DIRBASENAME=$(basename "$SCRIPTDIR")

[ $DIRBASENAME == "semla-license-manager-impact-example" ] || \
    ( echo "WARNING: for devcontainer to work this checkout must be in a directory called 'semla-license-manager-impact-example' (not $DIRBASENAME). See README.md")
    
# make sure we're not in a sparse checkout (cloud defaults to it)
git sparse-checkout disable

ARTIFACTS_URL=https://github.com/modelon-community/semla-license-manager-impact-example/releases/download/1.0.0-beta.1

SEMLA_OPENSSL_ZIP=SemlaOpenSSL-1.1.0-linux64-gcc485.zip
SEMLA_LIBJWT_ZIP=SemlaLibJWT-1.0.14-linux64-gcc485.zip
JANSSON_ZIP=jansson-1.0.4.zip
JWK2KEY=jwk2key
IMPACT_PUBLIC_KEY_TOOL_PEM=impact_public_key_tool.pem

for ART in ${SEMLA_OPENSSL_ZIP} ${SEMLA_LIBJWT_ZIP} ${JANSSON_ZIP} ${JWK2KEY} ${IMPACT_PUBLIC_KEY_TOOL_PEM}
do
    if [ ! -f ${ART} ]; then
        echo Downloading ${ART}
        curl -LO ${ARTIFACTS_URL}/${ART}
    fi
done
chmod +x ${JWK2KEY}

# Command to get current curl version (when updating to a new version here, also update filename and sha256 checksum in the cmake build system (search for the old curl version to find the locations to update)):
#    curl --version | head -n1 | cut -f2 -d' ' | sed -e 's/\./_/g'
CURL_VERSION="7_61_1"

CURL_RELEASE="curl-${CURL_VERSION}.zip"
if [ ! -f "${CURL_RELEASE}" ]; then
    echo "Downloading ${CURL_RELEASE}"
    curl -LO "https://github.com/curl/curl/archive/refs/tags/${CURL_RELEASE}"
fi


if [ ! -d ../SEMLA ]; then
    echo "Cloning SEMLA to ../SEMLA"
    git clone https://github.com/modelica/Encryption-and-Licensing.git ../SEMLA
fi

# generate keys for testing
if [ ! -d ../openssl_keys ]; then
    echo "Generating keys for testing in ../openssl_keys"
    mkdir ../openssl_keys
    (
        SOURCE_DIR=$(pwd)
        cd ../openssl_keys
        openssl genrsa -out "private_key_tool.pem" 4096
        openssl genrsa -out "private_key_lve.pem" 4096
        openssl rsa -pubout -in "private_key_tool.pem" -out "public_key_tool.pem"
        echo public_key_tool.pem > public_key_tools.txt 
        cp ${SOURCE_DIR}/${IMPACT_PUBLIC_KEY_TOOL_PEM} .
        echo ${IMPACT_PUBLIC_KEY_TOOL_PEM} >> public_key_tools.txt 
    )
fi

if [ ! -f jwt_keys/public_keys_jwt.txt ]; then
    ./update_jwt_keys_from_wellknown.sh
fi

if ! command -v cmake 2>&1 >/dev/null
then
    echo "cmake command not found"
    if [ ! -d build/venv ]; then
        echo Creating Python venv and installing cmake into it
        python -m venv build/venv
        . build/venv/bin/activate
        pip install cmake
    fi
    echo "Activate build virtual environment using 'source build/venv/bin/activate'"
fi

# if [ ! -f /usr/include/check.h ] ; then
#  TODO: disable check
# fi
