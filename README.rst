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
* `Python 3.9 <https://www.python.org/downloads/windows/>`_
* `Build Tools for Visual Studio <https://visualstudio.microsoft.com/downloads/>`_. This is in the "Tools for Visual Studio" section at the bottom of the page. The "Desktop development with C++" pack is needed from the installer.

Then from the command line install tox and CFFI using:

.. code-block:: sh

   pip install tox cffi

You can then build the source distribution packages using:

.. code-block:: sh

   python setup.py sdist


Linux
^^^^^

The `setup.py` file covers most things you will need to do to build and install from source. As pre-requisites you will need to install either from your OS repository or pip. You'll also need the Python development package for your Python version:

* `cffi`
* `tox`
* `pytest`

To build a source package run `python setup.py sdist`, to build a wheel package run `python setup.py bdist_wheel`. To test the build run `tox`. The `tox` tests rely on Python 3.9 being installed, if you do not have this version we recommend using `pyenv` to install it.

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

    $ USE_LOCAL_WOLFSSL=/path/to/wolfssl/install pip install .

If building wolfcrypt-py against a local wolfSSL library, wolfcrypt-py
will attempt to do native feature detection to enable/disable wolfcrypt-py
features based on how native wolfSSL has been compiled.  It uses the
<wolfssl/options.h> header to do feature detection.

Testing
-------

.. code-block:: python

    >>> from wolfcrypt.hashes import Sha256
    >>> Sha256('wolfcrypt').hexdigest()
    b'96e02e7b1cbcd6f104fe1fdb4652027a5505b68652b70095c6318f9dce0d1844'

Testing ``wolfcrypt``'s source code with ``tox``
------------------------------------------------

To run the unit tests in the source code, you'll need ``tox`` and a few other
requirements.

1. Make sure that the testing requirements are installed:

.. code-block:: console

    $ sudo -H pip install -r requirements/test.txt


2. Run ``tox``:

.. code-block:: console

    $ tox
    ...
    _________________________________ summary _________________________________
    py3: commands succeeded
    congratulations :)
