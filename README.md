layeredsec
==========

[![License](https://img.shields.io/github/license/joejacobs/rust-layeredsec)](https://mozilla.org/MPL/2.0/)
[![Build Status](https://travis-ci.org/joejacobs/rust-layeredsec.svg?branch=master)](https://travis-ci.org/joejacobs/rust-layeredsec)
[![Dependency Status](https://deps.rs/repo/github/joejacobs/rust-layeredsec/status.svg)](https://deps.rs/repo/github/joejacobs/rust-layeredsec)

Rust implementation of [Keybase's TripleSec][1] ([.onion][2]) encryption scheme
(versions 3 and 4) and other layered encryption schemes based on it. 

**UNAUDITED, USE AT YOUR OWN RISK**

TripleSec
---------
TripleSec itself is available via the `layeredsec::triplesec` module.
`triplesec::encrypt` encrypts a plaintext with the latest version of TripleSec
(currently v4) while `triplesec::decrypt` can decrypt ciphertext versions 3/4.
Alternatively you could use the `encrypt` and `decrypt` functions in
`triplesec::v3` and `triplesec::v4` if you want specific versions of TripleSec.

Custom Layered Encryption Schemes
---------------------------------
You should probably stick to the tried and tested TripleSec encryption scheme.
But if you know what you're doing and you really want/need to, then you could
use the `define_2_layer_encryption_scheme` and
`define_3_layer_encryption_scheme` macros in layeredsec to define custom layered
encryption scheme modules. The macros use 2 or 3 stream ciphers, 2 HMACs and can
optionally have a header (e.g. for magic bytes or version numbers). Right now
layeredsec has the following stream ciphers and HMACs:

Stream Ciphers

* AES-256-CTR (uses [RustCrypto][3])
* Camellia-256-CTR (uses [rust-openssl][4]/[OpenSSL][5])
* Serpent-256-CTR (uses [botan-rs][6]/[botan][7])
* Twofish-256-CTR (uses [botan-rs][6]/[botan][7])
* XChaCha20 (uses [RustCrypto][3])
* XSalsa20 (uses [RustCrypto][3])

HMAC (uses [RustCrypto][3])

* BLAKE2b
* Keccak-512
* SHA-512
* SHA3-512

For instance, the following defines the "Python version" of TripleSec v3:

    define_3_layer_encryption_module!(
        triplesec_v3_python,                            // module name
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x3],  // header
        XSalsa20,                                       // inner-most cipher
        Twofish256Ctr,                                  // middle cipher
        Aes256Ctr,                                      // outer-most cipher
        hmac_sha2,                                      // HMAC 1
        hmac_sha3                                       // HMAC 2
    );

License
-------
Copyright (C) 2019 Joe Jacobs

This Source Code Form is subject to the terms of the Mozilla Public License,
v. 2.0. If a copy of the MPL was not distributed with this file, You can obtain
one at https://mozilla.org/MPL/2.0/.

[1]: https://keybase.io/triplesec/
[2]: http://keybase5wmilwokqirssclfnsqrjdsi7jdir5wy7y7iu3tanwmtp6oid.onion/triplesec/
[3]: https://github.com/RustCrypto/
[4]: https://github.com/sfackler/rust-openssl/
[5]: https://www.openssl.org/
[6]: https://github.com/randombit/botan-rs/
[7]: https://botan.randombit.net/
