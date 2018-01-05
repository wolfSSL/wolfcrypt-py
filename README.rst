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

Testing
-------

.. code-block:: python

    >>> from wolfcrypt.hashes import Sha256
    >>> Sha256('wolfcrypt').hexdigest()
    b'96e02e7b1cbcd6f104fe1fdb4652027a5505b68652b70095c6318f9dce0d1844'
