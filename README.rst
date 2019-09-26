wolfcrypt: the wolfSSL Crypto Engine
====================================

.. image:: https://travis-ci.org/wolfSSL/wolfcrypt-py.svg?branch=master
    :target: https://travis-ci.org/wolfSSL/wolfcrypt-py

**wolfCrypt Python**, a.k.a. ``wolfcrypt`` is a Python module that encapsulates
**wolfSSL's wolfCrypt API**.

`wolfCrypt <https://wolfssl.com/wolfSSL/Products-wolfcrypt.html>`_ is a
lightweight, portable, C-language-based crypto library
targeted at IoT, embedded, and RTOS environments primarily because of its size,
speed, and feature set. It works seamlessly in desktop, enterprise, and cloud
environments as well. It is the crypto engine behind `wolfSSl's embedded ssl
library <https://wolfssl.com/wolfSSL/Products-wolfssl.html>`_.

Installation
------------

We provide Python wheels (prebuilt binaries) for OSX 64 bits and Linux 64 bits:

.. code-block:: bash

    $ pip install wolfcrypt

To build wolfcrypt-py against a local installation of the native C wolfSSL
library, use the USE_LOCAL_WOLFSSL variable.  This variable should be

wolfcrypt-py can be built against a local verison of the native wolfSSL
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
