#! /bin/bash
# Copyright (C) 2022 Modelon AB
set -euo pipefail

rm -rf extract/
unzip jansson*.zip -d extract/
JANSSON_LIBRARY_DIR=$(dirname $(find extract/ -name libjansson.a))
python3 license_manager/public_key_jwt/update_jwt_keys_from_wellknown.py --cmake-source-dir $(pwd) --jansson-library-dir ${JANSSON_LIBRARY_DIR}
rm -rf extract/
