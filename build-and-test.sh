#!/bin/bash
# Copyright (C) 2022 Modelon AB
set -euo pipefail

if [ -d build/venv]; then
    . build/venv/bin/activate
fi

cmake --preset linux
cmake --build --preset linux
