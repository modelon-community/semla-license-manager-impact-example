#!/bin/bash
set -euo pipefail

cmake --preset linux
cmake --build --preset linux
