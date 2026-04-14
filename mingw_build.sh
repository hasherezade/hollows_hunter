#!/bin/sh

set -e

cmake . \
    -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc \
    -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
    -DCMAKE_RC_COMPILER=x86_64-w64-mingw32-windres \
    -DCMAKE_SYSTEM_NAME=Windows-GNU \
    -DHH_PESIEVE_LINK_MODE=STATIC \
    -DLINK_STATICALLY=1

make
