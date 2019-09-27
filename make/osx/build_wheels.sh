set -e
set +x

for VER in 2.7 3.6 3.7; do
    PIP="pip${VER}"
    PYTHON="python${VER}"
    VENV="venv_${VER}"

    # update pip for newer TLS support
    curl https://bootstrap.pypa.io/get-pip.py | ${PYTHON}
    ${PIP} install -r requirements/setup.txt

    # update virtualenv
    ${PIP} install --upgrade virtualenv
    virtualenv -p ${PYTHON} ${VENV}
    . ./${VENV}/bin/activate

    ${PYTHON} setup.py bdist_wheel
    ${PIP} install -r requirements/test.txt
    set +e
    ${PIP} uninstall -y wolfcrypt
    set -e
    ${PIP} install wolfcrypt --no-index -f dist
    rm -rf tests/__pycache__
    py.test tests
    deactivate
done
