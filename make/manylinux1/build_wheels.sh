#!/bin/bash
set -e
set -x

docker run \
    --rm \
    -v `pwd`:/wolfcrypt-py \
    -w /wolfcrypt-py \
    quay.io/pypa/manylinux1_x86_64 \
    bash -c "make/manylinux1/build.sh"
