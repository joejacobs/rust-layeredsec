/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use layeredsec::*;

define_2_layer_encryption_module!(
    two_layered_headered,
    &[0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb],
    stream_xor_xchacha20,
    stream_xor_serpent256,
    hmac_sha3,
    hmac_sha2
);

define_2_layer_encryption_module!(
    two_layered_headerless,
    &[],
    stream_xor_xchacha20,
    stream_xor_aes256,
    hmac_sha2,
    hmac_sha3
);

define_3_layer_encryption_module!(
    three_layered_headered,
    &[0xf, 0xe, 0xd, 0xc],
    stream_xor_xchacha20,
    stream_xor_camellia256,
    stream_xor_serpent256,
    hmac_sha2,
    hmac_keccak
);

define_3_layer_encryption_module!(
    three_layered_headerless,
    &[],
    stream_xor_xchacha20,
    stream_xor_camellia256,
    stream_xor_aes256,
    hmac_keccak,
    hmac_sha2
);

fn encrypt_decrypt_test(
    encrypt: fn(Bytes, &Bytes) -> Result<Bytes, String>,
    decrypt: fn(Bytes, &Bytes) -> Result<Bytes, String>,
    header_sz: usize,
) {
    init().unwrap();
    let pt_bytes = b"the quick brown fox jumps over the lazy dog";
    let k_bytes = b"random-key-or-user-password";
    let pt = Bytes::from_vec(pt_bytes.to_vec());
    let k = Bytes::from_vec(k_bytes.to_vec());
    let ct = encrypt(pt.clone(), &k).unwrap();
    assert_eq!(ct.len(), header_sz + pt.len()); // verify ciphertext length
    let dec_pt = decrypt(ct, &k).unwrap();
    assert_eq!(pt.as_slice(), dec_pt.as_slice());
}

#[test]
fn can_encrypt_then_decrypt_with_3_layered_headered_encryption_module() {
    encrypt_decrypt_test(
        three_layered_headered::encrypt,
        three_layered_headered::decrypt,
        204,
    );
}

#[test]
fn can_encrypt_then_decrypt_with_3_layered_headerless_encryption_module() {
    encrypt_decrypt_test(
        three_layered_headerless::encrypt,
        three_layered_headerless::decrypt,
        200,
    );
}

#[test]
fn can_encrypt_then_decrypt_with_2_layered_headered_encryption_module() {
    encrypt_decrypt_test(
        two_layered_headered::encrypt,
        two_layered_headered::decrypt,
        196,
    );
}

#[test]
fn can_encrypt_then_decrypt_with_2_layered_headerless_encryption_module() {
    encrypt_decrypt_test(
        two_layered_headerless::encrypt,
        two_layered_headerless::decrypt,
        184,
    );
}

#[test]
fn can_encrypt_then_decrypt_with_triplesec_v3() {
    encrypt_decrypt_test(triplesec::v3::encrypt, triplesec::v3::decrypt, 208);
}

#[test]
fn can_encrypt_then_decrypt_with_triplesec_v4() {
    encrypt_decrypt_test(triplesec::v4::encrypt, triplesec::v4::decrypt, 192);
}
