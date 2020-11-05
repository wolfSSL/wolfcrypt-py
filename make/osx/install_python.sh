#!/bin/bash
set -euo pipefail
set -x

URLS=(
    'https://www.python.org/ftp/python/2.7.18/python-2.7.18-macosx10.9.pkg'
    'https://www.python.org/ftp/python/3.7.9/python-3.7.9-macosx10.9.pkg'
    'https://www.python.org/ftp/python/3.8.6/python-3.8.6-macosx10.9.pkg'
)

for url in "${URLS[@]}"; do
    curl -Lo /tmp/python.pkg "$url"
    sudo installer -pkg /tmp/python.pkg -target /
done
