#!/bin/bash
set -e
set -x

docker run \
    --rm \
    -v `pwd`:/wolfcrypt-py \
    -w /wolfcrypt-py \
    wolfssl/manylinux1-x86_64 \
    bash -c "make/manylinux1/build.sh"
