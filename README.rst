wolfcrypt: the wolfSSL Crypto Engine
====================================

**wolfCrypt Python**, a.k.a. ``wolfcrypt`` is a Python module that encapsulates
**wolfSSL's wolfCrypt API**.

`wolfCrypt <https://wolfssl.com/wolfSSL/Products-wolfcrypt.html>`_ is a
lightweight, portable, C-language-based crypto library
targeted at IoT, embedded, and RTOS environments primarily because of its size,
speed, and feature set. It works seamlessly in desktop, enterprise, and cloud
environments as well. It is the crypto engine behind `wolfSSL's embedded ssl
library <https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_.

Compiling
---------

Windows
^^^^^^^

Install the following on Windows:

* `CMake <https://cmake.org/download/>`_
* `Git <https://git-scm.com/download/win>`_
* `Python 3.10 or newer <https://www.python.org/downloads/windows/>`_
* `Build Tools for Visual Studio <https://visualstudio.microsoft.com/downloads/>`_. This is in the "Tools for Visual Studio" section at the bottom of the page. The "Desktop development with C++" pack is needed from the installer.

Then from the command line install `uv` using:

.. code-block:: sh

   pip install uv

You can then build the source distribution packages using:

.. code-block:: sh

   uv build --sdist


Linux
^^^^^

The `setup.py` file covers most things you will need to do to build and install from source. As pre-requisites you will need to install either from your OS repository or pip. You'll also need the Python development package for your Python version:

* `uv`

To build a source package run `uv build --sdist`, to build a wheel package run `uv build --wheel`. To test the build run `uv run pytest`. The tests rely on Python 3.10 or later being installed.

Installation
------------

We provide Python wheels (prebuilt binaries) for OSX 64 bits and Linux 64 bits:

.. code-block:: bash

    $ pip install wolfcrypt

To build wolfcrypt-py against a local installation of the native C wolfSSL
library, use the USE_LOCAL_WOLFSSL variable.  This variable should be

wolfcrypt-py can be built against a local version of the native wolfSSL
library by using pip with the USE_LOCAL_WOLFSSL variable. USE_LOCAL_WOLFSSL
should be set equal to the installation path for the wolfSSL library:

.. code-block:: bash

    $ USE_LOCAL_WOLFSSL=/path/to/wolfssl/install uv sync

If building wolfcrypt-py against a local wolfSSL library, wolfcrypt-py
will attempt to do native feature detection to enable/disable wolfcrypt-py
features based on how native wolfSSL has been compiled.  It uses the
<wolfssl/options.h> header to do feature detection.

Testing
-------
.. code-block:: console
   $ uv run python3

.. code-block:: python

    >>> from wolfcrypt.hashes import Sha256
    >>> Sha256('wolfcrypt').hexdigest()
    b'96e02e7b1cbcd6f104fe1fdb4652027a5505b68652b70095c6318f9dce0d1844'

Testing ``wolfcrypt``'s source code with ``pytest``
---------------------------------------------------

To run the unit tests in the source code, you'll need ``uv`` and a few other
requirements.

1. Make sure that the testing requirements are installed:

.. code-block:: console

    $ uv sync --dev


2. Run ``pytest``:

.. code-block:: console

    $ uv run pytest
    ======================================= test session starts =======================================
    platform linux -- Python 3.10.12, pytest-9.1.1, pluggy-1.6.0
    rootdir: /some_directory/wolfcrypt-py
    configfile: pyproject.toml
    collected 165 items

    tests/test_aesgcmstream.py .........                                                        [  5%]
    tests/test_asn.py ..                                                                        [  6%]
    tests/test_chacha20poly1305.py ......                                                       [ 10%]
    tests/test_ciphers.py ...........................................                           [ 36%]
    tests/test_delete_descriptor_binding.py .................                                   [ 46%]
    tests/test_error_string.py ....                                                             [ 49%]
    tests/test_hashes.py ...........................                                            [ 65%]
    tests/test_hkdf.py ........                                                                 [ 70%]
    tests/test_mldsa.py ..............................                                          [ 88%]
    tests/test_mlkem.py ............                                                            [ 95%]
    tests/test_pwdbased.py .                                                                    [ 96%]
    tests/test_random.py ......                                                                 [100%]

    ======================================= 165 passed in 7.09s =======================================
