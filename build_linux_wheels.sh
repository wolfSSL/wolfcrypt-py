#!/bin/bash
set -e
set -x

# create docker container

CONT=$(date +%s)

TAG=manylinux1-x86_64

docker run \
    -d \
    -v `pwd`:/wolfcrypt-py \
    -w /wolfcrypt-py \
    --name ${CONT} \
    ${TAG} \
    bash -c "tail -f /var/log/lastlog"

docker exec ${CONT} bash -c "if [ -d dist ]; then mv dist tmpdist; fi"

for PYVERSION in cp27-cp27m cp27-cp27mu cp34-cp34m cp35-cp35m cp36-cp36m
do
    docker exec ${CONT} /opt/python/${PYVERSION}/bin/python setup.py bdist_wheel
    docker exec ${CONT} rm -rf .eggs
done

docker exec ${CONT} bash -c 'for i in $(ls dist/*.whl); do auditwheel repair $i -w tmpdist; done;'
docker exec ${CONT} bash -c "rm -rf dist"
docker exec ${CONT} bash -c "mv tmpdist dist"

docker rm -f ${CONT}