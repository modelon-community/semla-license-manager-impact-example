#!/bin/bash
set -euo pipefail

if [ -d build/venv]; then
    . build/venv/bin/activate
fi

cmake --preset linux-debug-no-warnings
cmake --build --preset linux-debug-no-warnings
