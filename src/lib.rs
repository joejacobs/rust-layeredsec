/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

pub mod streamciphers;
mod utils;

pub use self::utils::ByteVec;
use self::utils::*;

use hmac::{Hmac, Mac};
use openssl::pkcs5::scrypt;
use rand::{prelude::RngCore, rngs::OsRng};
use sha2;
use sha3;
use stream_cipher::generic_array::typenum::{U48, U64};
use streamciphers::StreamCipher;

const CIPHER_KEY_SZ: usize = 32;
const HMAC_KEY_SZ: usize = 48;
const HMAC_SZ: usize = 64;
const SALT_SZ: usize = 16;

// scrypt params
const SCRYPT_N: u64 = 1 << 15;
const SCRYPT_P: u64 = 1;
const SCRYPT_R: u64 = 8;
const SCRYPT_MEM: u64 = (SCRYPT_N + SCRYPT_P) * SCRYPT_R * 129;

// output buffer indices for generic layered encryption
const SALT_FST: usize = 0;
const HMAC0_FST: usize = SALT_FST + SALT_SZ;
const HMAC1_FST: usize = HMAC0_FST + HMAC_SZ;
const NONCE_FST: usize = HMAC1_FST + HMAC_SZ;

// abbreviations of common types for convenience
type HmacFn = fn(&[u8], &ByteArr<U48>) -> ByteArr<U64>;

// define a 2-layered encryption module
#[macro_export]
macro_rules! define_2_layer_encryption_module {
    (
        $name:ident,
        $header:expr,
        $cipher1:ident,
        $cipher2:ident,
        $hmac1:ident,
        $hmac2:ident
    ) => {
        pub mod $name {
            use super::*;

            pub fn decrypt(ct: ByteVec, k: &ByteVec) -> Result<ByteVec, String> {
                generic_double_decrypt(ct, k, $header, ($cipher1(), $cipher2()), ($hmac1, $hmac2))
            }

            pub fn encrypt(pt: ByteVec, k: &ByteVec) -> Result<ByteVec, String> {
                generic_double_encrypt(pt, k, $header, ($cipher1(), $cipher2()), ($hmac1, $hmac2))
            }
        }
    };
}

// define a 3-layered encryption module
#[macro_export]
macro_rules! define_3_layer_encryption_module {
    (
        $name:ident,
        $header:expr,
        $cipher1:ident,
        $cipher2:ident,
        $cipher3:ident,
        $hmac1:ident,
        $hmac2:ident
    ) => {
        pub mod $name {
            use super::*;

            pub fn decrypt(ct: ByteVec, k: &ByteVec) -> Result<ByteVec, String> {
                generic_triple_decrypt(
                    ct,
                    k,
                    $header,
                    ($cipher1(), $cipher2(), $cipher3()),
                    ($hmac1, $hmac2),
                )
            }

            pub fn encrypt(pt: ByteVec, k: &ByteVec) -> Result<ByteVec, String> {
                generic_triple_encrypt(
                    pt,
                    k,
                    $header,
                    ($cipher1(), $cipher2(), $cipher3()),
                    ($hmac1, $hmac2),
                )
            }
        }
    };
}

// define triplesec module
pub mod triplesec {
    use super::streamciphers::{Aes256Ctr, Twofish256Ctr, XSalsa20};
    use super::*;

    define_3_layer_encryption_module!(
        v3,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x3],
        XSalsa20,
        Twofish256Ctr,
        Aes256Ctr,
        hmac_sha2,
        hmac_keccak
    );

    define_2_layer_encryption_module!(
        v4,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x4],
        XSalsa20,
        Aes256Ctr,
        hmac_sha2,
        hmac_sha3
    );

    pub fn decrypt(ct: ByteVec, k: &ByteVec) -> Res<ByteVec> {
        if ct.len() < NONCE_FST + 9 {
            return Err("ciphertext is too short".to_string());
        }

        if ct.eq(0, 4, &[0x1c, 0x94, 0xd7, 0xde])? == 0 {
            return Err("magic number error".to_string());
        }

        if ct.eq(4, 8, &[0x0, 0x0, 0x0, 0x3])? == 1 {
            v3::decrypt(ct, k)
        } else if ct.eq(4, 8, &[0x0, 0x0, 0x0, 0x4])? == 1 {
            v4::decrypt(ct, k)
        } else {
            Err("unsupported triplesec version".to_string())
        }
    }

    pub fn encrypt(pt: ByteVec, k: &ByteVec) -> Res<ByteVec> {
        v4::encrypt(pt, k)
    }
}

fn cipher_decrypt<T: StreamCipher>(
    cipher: &T,
    buf: ByteVec,
    key: &ByteArr<T::KeySize>,
) -> Res<ByteVec> {
    let nonce = ByteArr::from_slice(buf.get_slice(0, cipher.nonce_size())?)?;
    let ct = ByteVec::from_slice(buf.get_slice(cipher.nonce_size(), buf.len())?)?;
    cipher.apply_keystream(ct, key, &nonce)
}

fn cipher_encrypt<T: StreamCipher>(
    cipher: &T,
    pt: ByteVec,
    key: &ByteArr<T::KeySize>,
) -> Res<ByteVec> {
    let buf_sz = cipher.nonce_size() + pt.len();
    let nonce = ByteArr::random()?;
    let ct = cipher.apply_keystream(pt, &key, &nonce)?;

    let mut buf = ByteVec::blank(buf_sz);
    buf.copy_from_slice(0, cipher.nonce_size(), nonce.as_slice())?;
    buf.copy_from_slice(cipher.nonce_size(), buf_sz, ct.as_slice())?;
    Ok(buf)
}

pub fn generic_double_decrypt<T, U>(
    ct: ByteVec,
    key: &ByteVec,
    header: &[u8],
    ciphers: (T, U),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<ByteVec>
where
    T: StreamCipher,
    U: StreamCipher,
{
    if ct.len() < header.len() + NONCE_FST + 1 {
        return Err("ciphertext is too short".to_string());
    }

    if key.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac0_fst = HMAC0_FST + header.len();
    let nonce_fst = NONCE_FST + header.len();

    if salt_fst > 0 && ct.eq(header_fst, salt_fst, header)? == 0 {
        return Err("header error".to_string());
    }

    // stretch key
    let keys = stretch_key(key, ct.get_slice(salt_fst, hmac0_fst)?, 2, 2)?;
    let hmac0_key = ByteArr::from_slice(keys[0].as_slice())?;
    let hmac1_key = ByteArr::from_slice(keys[1].as_slice())?;
    let cipher1_key = ByteArr::from_slice(keys[2].as_slice())?;
    let cipher0_key = ByteArr::from_slice(keys[3].as_slice())?;

    // verify hmacs
    let mut buf = ct.clone();
    let lst = ct.len() - (2 * HMAC_SZ);
    buf.copy_from_slice(hmac0_fst, lst, ct.get_slice(nonce_fst, ct.len())?)?;
    let hmac0 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hmac0_key);
    let hmac1 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hmac1_key);

    let mut hmacs_out = ByteVec::blank(2 * HMAC_SZ);
    hmacs_out.copy_from_slice(0, HMAC_SZ, hmac0.as_slice())?;
    hmacs_out.copy_from_slice(HMAC_SZ, 2 * HMAC_SZ, hmac1.as_slice())?;

    if ct.eq(hmac0_fst, nonce_fst, hmacs_out.as_slice())? == 0 {
        return Err("authentication error".to_string());
    }

    // get ciphertext from input buffer and decrypt it
    let pt2 = ByteVec::from_slice(ct.get_slice(nonce_fst, ct.len())?)?;
    let pt1 = cipher_decrypt(&ciphers.1, pt2, &cipher1_key)?;
    let pt0 = cipher_decrypt(&ciphers.0, pt1, &cipher0_key)?;

    // verify plaintext size
    if nonce_fst + ciphers.1.nonce_size() + ciphers.0.nonce_size() + pt0.len() != ct.len() {
        return Err("decryption error".to_string());
    }

    Ok(pt0)
}

pub fn generic_double_encrypt<T, U>(
    pt: ByteVec,
    key: &ByteVec,
    header: &[u8],
    ciphers: (T, U),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<ByteVec>
where
    T: StreamCipher,
    U: StreamCipher,
{
    if pt.len() < 1 {
        return Err("empty plaintext".to_string());
    }

    if key.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac0_fst = HMAC0_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let nonce_fst = NONCE_FST + header.len();

    // create output buffer
    let buf_sz = nonce_fst + ciphers.1.nonce_size() + ciphers.0.nonce_size() + pt.len();
    let mut buf = ByteVec::blank(buf_sz);
    buf.copy_from_slice(header_fst, salt_fst, header)?;

    // generate salt and stretch key
    OsRng.fill_bytes(buf.get_mut_slice(salt_fst, hmac0_fst)?);
    let keys = stretch_key(key, buf.get_slice(salt_fst, hmac0_fst)?, 2, 2)?;
    let hmac0_key = ByteArr::from_slice(keys[0].as_slice())?;
    let hmac1_key = ByteArr::from_slice(keys[1].as_slice())?;
    let cipher1_key = ByteArr::from_slice(keys[2].as_slice())?;
    let cipher0_key = ByteArr::from_slice(keys[3].as_slice())?;

    // encrypt plaintext and add it to the output buffer
    let ct0 = cipher_encrypt(&ciphers.0, pt, &cipher0_key)?;
    let ct1 = cipher_encrypt(&ciphers.1, ct0, &cipher1_key)?;

    // calculate hmac and add to output buffer
    let lst = hmac0_fst + ct1.len();
    buf.copy_from_slice(hmac0_fst, lst, ct1.as_slice())?;
    let hmac0 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hmac0_key);
    let hmac1 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hmac1_key);

    // construct output
    buf.copy_from_slice(hmac0_fst, hmac1_fst, hmac0.as_slice())?;
    buf.copy_from_slice(hmac1_fst, nonce_fst, hmac1.as_slice())?;
    buf.copy_from_slice(nonce_fst, buf_sz, ct1.as_slice())?;

    Ok(buf)
}

pub fn generic_triple_decrypt<T, U, V>(
    ct: ByteVec,
    key: &ByteVec,
    header: &[u8],
    ciphers: (T, U, V),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<ByteVec>
where
    T: StreamCipher,
    U: StreamCipher,
    V: StreamCipher,
{
    if ct.len() < header.len() + NONCE_FST + 1 {
        return Err("ciphertext is too short".to_string());
    }

    if key.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac0_fst = HMAC0_FST + header.len();
    let nonce_fst = NONCE_FST + header.len();

    if salt_fst > 0 && ct.eq(header_fst, salt_fst, header)? == 0 {
        return Err("header error".to_string());
    }

    // stretch key
    let keys = stretch_key(key, ct.get_slice(salt_fst, hmac0_fst)?, 2, 3)?;
    let hmac0_key = ByteArr::from_slice(keys[0].as_slice())?;
    let hmac1_key = ByteArr::from_slice(keys[1].as_slice())?;
    let cipher2_key = ByteArr::from_slice(keys[2].as_slice())?;
    let cipher1_key = ByteArr::from_slice(keys[3].as_slice())?;
    let cipher0_key = ByteArr::from_slice(keys[4].as_slice())?;

    // verify hmacs
    let mut buf = ct.clone();
    let lst = ct.len() - (2 * HMAC_SZ);
    buf.copy_from_slice(hmac0_fst, lst, ct.get_slice(nonce_fst, ct.len())?)?;
    let hmac0 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hmac0_key);
    let hmac1 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hmac1_key);

    let mut hmacs_out = ByteVec::blank(2 * HMAC_SZ);
    hmacs_out.copy_from_slice(0, HMAC_SZ, hmac0.as_slice())?;
    hmacs_out.copy_from_slice(HMAC_SZ, 2 * HMAC_SZ, hmac1.as_slice())?;

    if ct.eq(hmac0_fst, nonce_fst, hmacs_out.as_slice())? == 0 {
        return Err("authentication error".to_string());
    }

    // get ciphertext from input buffer and decrypt it
    let pt3 = ByteVec::from_slice(ct.get_slice(nonce_fst, ct.len())?)?;
    let pt2 = cipher_decrypt(&ciphers.2, pt3, &cipher2_key)?;
    let pt1 = cipher_decrypt(&ciphers.1, pt2, &cipher1_key)?;
    let pt0 = cipher_decrypt(&ciphers.0, pt1, &cipher0_key)?;

    // verify plaintext size
    if nonce_fst
        + ciphers.2.nonce_size()
        + ciphers.1.nonce_size()
        + ciphers.0.nonce_size()
        + pt0.len()
        != ct.len()
    {
        return Err("decryption error".to_string());
    }

    Ok(pt0)
}

pub fn generic_triple_encrypt<T, U, V>(
    pt: ByteVec,
    key: &ByteVec,
    header: &[u8],
    ciphers: (T, U, V),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<ByteVec>
where
    T: StreamCipher,
    U: StreamCipher,
    V: StreamCipher,
{
    if pt.len() < 1 {
        return Err("empty plaintext".to_string());
    }

    if key.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac0_fst = HMAC0_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let nonce_fst = NONCE_FST + header.len();

    // create output buffer
    let buf_sz = nonce_fst
        + ciphers.2.nonce_size()
        + ciphers.1.nonce_size()
        + ciphers.0.nonce_size()
        + pt.len();
    let mut buf = ByteVec::blank(buf_sz);
    buf.copy_from_slice(header_fst, salt_fst, header)?;

    // generate salt and stretch key
    OsRng.fill_bytes(buf.get_mut_slice(salt_fst, hmac0_fst)?);
    let keys = stretch_key(key, buf.get_slice(salt_fst, hmac0_fst)?, 2, 3)?;
    let hmac0_key = ByteArr::from_slice(keys[0].as_slice())?;
    let hmac1_key = ByteArr::from_slice(keys[1].as_slice())?;
    let cipher2_key = ByteArr::from_slice(keys[2].as_slice())?;
    let cipher1_key = ByteArr::from_slice(keys[3].as_slice())?;
    let cipher0_key = ByteArr::from_slice(keys[4].as_slice())?;

    // encrypt plaintext and add it to the output buffer
    let ct0 = cipher_encrypt(&ciphers.0, pt, &cipher0_key)?;
    let ct1 = cipher_encrypt(&ciphers.1, ct0, &cipher1_key)?;
    let ct2 = cipher_encrypt(&ciphers.2, ct1, &cipher2_key)?;

    // calculate hmac and add to output buffer
    let lst = hmac0_fst + ct2.len();
    buf.copy_from_slice(hmac0_fst, lst, ct2.as_slice())?;
    let hmac0 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hmac0_key);
    let hmac1 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hmac1_key);

    // construct output
    buf.copy_from_slice(hmac0_fst, hmac1_fst, hmac0.as_slice())?;
    buf.copy_from_slice(hmac1_fst, nonce_fst, hmac1.as_slice())?;
    buf.copy_from_slice(nonce_fst, buf_sz, ct2.as_slice())?;

    Ok(buf)
}

pub fn hmac_blake2b(buf: &[u8], k: &ByteArr<U48>) -> ByteArr<U64> {
    let mut hmac = Hmac::<blake2::Blake2b>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    ByteArr::from_generic_array(hmac.result().code())
}

pub fn hmac_keccak(buf: &[u8], k: &ByteArr<U48>) -> ByteArr<U64> {
    let mut hmac = Hmac::<sha3::Keccak512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    ByteArr::from_generic_array(hmac.result().code())
}

pub fn hmac_sha2(buf: &[u8], k: &ByteArr<U48>) -> ByteArr<U64> {
    let mut hmac = Hmac::<sha2::Sha512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    ByteArr::from_generic_array(hmac.result().code())
}

pub fn hmac_sha3(buf: &[u8], k: &ByteArr<U48>) -> ByteArr<U64> {
    let mut hmac = Hmac::<sha3::Sha3_512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    ByteArr::from_generic_array(hmac.result().code())
}

pub fn init() {
    openssl::init()
}

fn stretch_key(
    key: &ByteVec,
    salt: &[u8],
    n_hmac_keys: usize,
    n_cipher_keys: usize,
) -> Res<Vec<ByteVec>> {
    // stretch the key with scrypt
    let mut all_keys =
        ByteVec::blank((n_hmac_keys * HMAC_KEY_SZ) + (n_cipher_keys * CIPHER_KEY_SZ));
    let mut key_vec = Vec::with_capacity(n_hmac_keys + n_cipher_keys);

    if let Err(e) = scrypt(
        key.as_slice(),
        salt,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        SCRYPT_MEM,
        all_keys.as_mut_slice(),
    ) {
        e.errors();
        return Err("scrypt error".to_string());
    }

    // extract the individual keys
    let mut fst;
    let mut lst = 0;

    for _ in 0..n_hmac_keys {
        fst = lst;
        lst += HMAC_KEY_SZ;
        key_vec.push(ByteVec::from_slice(all_keys.get_slice(fst, lst)?)?);
    }

    for _ in 0..n_cipher_keys {
        fst = lst;
        lst += CIPHER_KEY_SZ;
        key_vec.push(ByteVec::from_slice(all_keys.get_slice(fst, lst)?)?);
    }

    Ok(key_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_decrypt_all_ciphertexts_with_triplesec_decrypt() {
        let v3_json_str = include_str!("./unittests/triplesec-v3-tests.json");
        let v4_json_str = include_str!("./unittests/triplesec-v4-tests.json");
        let mut test_vectors = testutils::parse_test_vectors(v3_json_str).unwrap();
        let mut test_vectors_v4 = testutils::parse_test_vectors(v4_json_str).unwrap();
        test_vectors.append(&mut test_vectors_v4);

        for v in test_vectors {
            let pt = triplesec::decrypt(v.ct, &v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_decrypt_with_triplesec_v3() {
        let json_str = include_str!("./unittests/triplesec-v3-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let pt = triplesec::v3::decrypt(v.ct, &v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_decrypt_with_triplesec_v4() {
        let json_str = include_str!("./unittests/triplesec-v4-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let pt = triplesec::v4::decrypt(v.ct, &v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }
}
