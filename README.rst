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

.. code-block:: bash

    python -c "from wolfcrypt.hashes import Sha; print Sha().hexdigest()"

expected output: **da39a3ee5e6b4b0d3255bfef95601890afd80709**
