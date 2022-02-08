Symmetric Key Algorithms
========================

.. module:: wolfcrypt.ciphers

**Symmetric key algorithms** are encryption algorithms that use the **same
cryptographic key** for both encryption and decryption of data.
This operation is also known as **Symmetric Key Encryption**.

Symmetric Key Encryption Classes
--------------------------------

Interface
~~~~~~~~~

All **Symmetric Key Ciphers** available in this module implements the following
interface:

.. autoclass:: _Cipher
    :members:
    :inherited-members:

AES
~~~

.. autoclass:: Aes
    :members:
    :inherited-members:

**Example:**

.. doctest::

    >>> from wolfcrypt.ciphers import Aes, MODE_CBC
    >>>
    >>> cipher = Aes(b'0123456789abcdef', MODE_CBC, b'1234567890abcdef')
    >>> ciphertext = cipher.encrypt('now is the time ')
    >>> ciphertext
    b'\x95\x94\x92W_B\x81S,\xcc\x9dFw\xa23\xcb'
    >>> cipher.decrypt(ciphertext)
    b'now is the time '

Triple DES
~~~~~~~~~~

.. autoclass:: Des3
    :members:
    :inherited-members:

**Example:**

.. doctest::

    >>> from wolfcrypt.ciphers import Des3, MODE_CBC
    >>>
    >>> cipher = Des3(b'0123456789abcdeffedeba98', MODE_CBC, b'12345678')
    >>> ciphertext = cipher.encrypt('now is the time ')
    >>> ciphertext
    b'l\x04\xd0$\xe8\x0c1\xd6\x1b\x07}V\xa6ty\xe8'
    >>> cipher.decrypt(ciphertext)
    b'now is the time '
