/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

mod utils;

pub use self::utils::Bytes;
use self::utils::*;
use botan::{Cipher, CipherDirection};
use chacha20::XChaCha20;
use hmac::{Hmac, Mac};
use openssl::{nid, pkcs5::scrypt, symm};
use rand::{prelude::RngCore, rngs::OsRng};
use sha2;
use sha3;
use sodiumoxide::crypto::stream::xsalsa20;
use stream_cipher::{generic_array::GenericArray, NewStreamCipher, SyncStreamCipher};
use zeroize::Zeroize;

const CIPHER_KEY_SZ: usize = 32;
const HMAC_KEY_SZ: usize = 48;
const HMAC_SZ: usize = 64;
const SALT_SZ: usize = 16;

// NIDs for different OpenSSL ciphers
const NIDAES: i32 = 906;
const NIDCAM: i32 = 971;

// scrypt params
const SCRYPT_N: u64 = 1 << 15;
const SCRYPT_P: u64 = 1;
const SCRYPT_R: u64 = 8;
const SCRYPT_MEM: u64 = (SCRYPT_N + SCRYPT_P) * SCRYPT_R * 129;

// output buffer indices for generic layered encryption
const SALT_FST: usize = 0;
const HMAC1_FST: usize = SALT_FST + SALT_SZ;
const HMAC2_FST: usize = HMAC1_FST + HMAC_SZ;
const CT_FST: usize = HMAC2_FST + HMAC_SZ;

// safe byte arrays of varying sizes
define_safe_byte_array!(Safe16B, 16);
define_safe_byte_array!(Safe24B, 24);
define_safe_byte_array!(Safe32B, 32);
define_safe_byte_array!(Safe48B, 48);
define_safe_byte_array!(Safe64B, 64);

// abbreviations of common types for convenience
type EncFn<T> = fn(Bytes, &T, &Safe32B) -> Res<Bytes>;
type DecFn<T> = fn(Bytes, &T, &Safe32B) -> Res<Bytes>;
type HmacFn = fn(&[u8], &Safe48B) -> Res<Safe64B>;

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

            pub fn decrypt(ct: Bytes, k: &Bytes) -> Result<Bytes, String> {
                generic_double_decrypt(ct, k, $header, ($cipher1, $cipher2), ($hmac1, $hmac2))
            }

            pub fn encrypt(pt: Bytes, k: &Bytes) -> Result<Bytes, String> {
                generic_double_encrypt(pt, k, $header, ($cipher1, $cipher2), ($hmac1, $hmac2))
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

            pub fn decrypt(ct: Bytes, k: &Bytes) -> Result<Bytes, String> {
                generic_triple_decrypt(
                    ct,
                    k,
                    $header,
                    ($cipher1, $cipher2, $cipher3),
                    ($hmac1, $hmac2),
                )
            }

            pub fn encrypt(pt: Bytes, k: &Bytes) -> Result<Bytes, String> {
                generic_triple_encrypt(
                    pt,
                    k,
                    $header,
                    ($cipher1, $cipher2, $cipher3),
                    ($hmac1, $hmac2),
                )
            }
        }
    };
}

// define triplesec module
pub mod triplesec {
    use super::*;

    define_3_layer_encryption_module!(
        v3,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x3],
        stream_xor_xsalsa20,
        stream_xor_twofish256,
        stream_xor_aes256,
        hmac_sha2,
        hmac_keccak
    );

    define_2_layer_encryption_module!(
        v4,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x4],
        stream_xor_xsalsa20,
        stream_xor_aes256,
        hmac_sha2,
        hmac_sha3
    );

    pub fn decrypt(ct: Bytes, k: &Bytes) -> Res<Bytes> {
        if ct.len() < CT_FST + 9 {
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

    pub fn encrypt(pt: Bytes, k: &Bytes) -> Res<Bytes> {
        v4::encrypt(pt, k)
    }
}

fn cipher_decrypt<T>(dec_fn: DecFn<T>, buf: Bytes, k: &Safe32B) -> Res<Bytes>
where
    T: FromSlice + Size,
{
    let ct_sz = buf.len() - T::size();
    let iv = T::from_slice(buf.get_slice(0, T::size())?)?;
    let mut ct = Bytes::blank(ct_sz);
    ct.copy_from_slice(0, ct_sz, buf.get_slice(T::size(), buf.len())?)?;
    dec_fn(ct, &iv, k)
}

fn cipher_encrypt<T>(enc_fn: EncFn<T>, pt: Bytes, k: &Safe32B) -> Res<Bytes>
where
    T: AsSlice + Random + Size,
{
    let buf_sz = T::size() + pt.len();
    let iv = T::random()?;
    let ct = enc_fn(pt, &iv, k)?;

    let mut buf = Bytes::blank(buf_sz);
    buf.copy_from_slice(0, T::size(), iv.as_slice())?;
    buf.copy_from_slice(T::size(), buf_sz, ct.as_slice())?;
    Ok(buf)
}

pub fn generic_double_decrypt<T, U>(
    ct: Bytes,
    k: &Bytes,
    header: &[u8],
    dec_fn: (DecFn<T>, DecFn<U>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: FromSlice + Size,
    U: FromSlice + Size,
{
    if ct.len() < header.len() + CT_FST + 1 {
        return Err("ciphertext is too short".to_string());
    }

    if k.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let ct_fst = CT_FST + header.len();

    if salt_fst > 0 && ct.eq(header_fst, salt_fst, header)? == 0 {
        return Err("header error".to_string());
    }

    // stretch key
    let (ckeys, hkeys) = stretch_key(k.as_slice(), ct.get_slice(salt_fst, hmac1_fst)?, 3)?;

    // verify hmacs
    let mut buf = ct.clone();
    let lst = ct.len() - (2 * HMAC_SZ);
    buf.copy_from_slice(hmac1_fst, lst, ct.get_slice(ct_fst, ct.len())?)?;
    let hmac1 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hkeys[0])?;
    let hmac2 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hkeys[1])?;

    let mut hmacs_out = Bytes::blank(2 * HMAC_SZ);
    hmacs_out.copy_from_slice(0, HMAC_SZ, hmac1.as_slice())?;
    hmacs_out.copy_from_slice(HMAC_SZ, 2 * HMAC_SZ, hmac2.as_slice())?;

    if ct.eq(hmac1_fst, ct_fst, hmacs_out.as_slice())? == 0 {
        return Err("authentication error".to_string());
    }

    // get ciphertext from input buffer and decrypt it
    let buf = Bytes::from_vec(ct.get_slice(ct_fst, ct.len())?.into());
    let pt2 = cipher_decrypt(dec_fn.1, buf, &ckeys[0])?;
    let pt1 = cipher_decrypt(dec_fn.0, pt2, &ckeys[1])?;

    // verify plaintext size
    if ct_fst + U::size() + T::size() + pt1.len() != ct.len() {
        return Err("decryption error".to_string());
    }

    Ok(pt1)
}

pub fn generic_double_encrypt<T, U>(
    pt: Bytes,
    k: &Bytes,
    header: &[u8],
    enc_fn: (EncFn<T>, EncFn<U>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: AsSlice + Random + Size,
    U: AsSlice + Random + Size,
{
    if pt.len() < 1 {
        return Err("empty plaintext".to_string());
    }

    if k.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let hmac2_fst = HMAC2_FST + header.len();
    let ct_fst = CT_FST + header.len();

    // create output buffer
    let buf_sz = ct_fst + T::size() + U::size() + pt.len();
    let mut buf = Bytes::blank(buf_sz);
    buf.copy_from_slice(header_fst, salt_fst, header)?;

    // generate salt and stretch key
    OsRng.fill_bytes(buf.get_mut_slice(salt_fst, hmac1_fst)?);
    let (ckeys, hkeys) = stretch_key(k.as_slice(), buf.get_slice(salt_fst, hmac1_fst)?, 3)?;

    // encrypt plaintext and add it to the output buffer
    let ct1 = cipher_encrypt(enc_fn.0, pt, &ckeys[1])?;
    let ct2 = cipher_encrypt(enc_fn.1, ct1, &ckeys[0])?;

    // calculate hmac and add to output buffer
    let lst = hmac1_fst + ct2.len();
    buf.copy_from_slice(hmac1_fst, lst, ct2.as_slice())?;
    let hmac1 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hkeys[0])?;
    let hmac2 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hkeys[1])?;

    // construct output
    buf.copy_from_slice(hmac1_fst, hmac2_fst, hmac1.as_slice())?;
    buf.copy_from_slice(hmac2_fst, ct_fst, hmac2.as_slice())?;
    buf.copy_from_slice(ct_fst, buf_sz, ct2.as_slice())?;

    Ok(buf)
}

pub fn generic_triple_decrypt<T, U, V>(
    ct: Bytes,
    k: &Bytes,
    header: &[u8],
    dec_fn: (DecFn<T>, DecFn<U>, DecFn<V>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: FromSlice + Size,
    U: FromSlice + Size,
    V: FromSlice + Size,
{
    if ct.len() < header.len() + CT_FST + 1 {
        return Err("ciphertext is too short".to_string());
    }

    if k.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let ct_fst = CT_FST + header.len();

    if salt_fst > 0 && ct.eq(header_fst, salt_fst, header)? == 0 {
        return Err("header error".to_string());
    }

    // stretch key
    let (ckeys, hkeys) = stretch_key(k.as_slice(), ct.get_slice(salt_fst, hmac1_fst)?, 3)?;

    // verify hmacs
    let mut buf = ct.clone();
    let lst = ct.len() - (2 * HMAC_SZ);
    buf.copy_from_slice(hmac1_fst, lst, ct.get_slice(ct_fst, ct.len())?)?;
    let hmac1 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hkeys[0])?;
    let hmac2 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hkeys[1])?;

    let mut hmacs_out = Bytes::blank(2 * HMAC_SZ);
    hmacs_out.copy_from_slice(0, HMAC_SZ, hmac1.as_slice())?;
    hmacs_out.copy_from_slice(HMAC_SZ, 2 * HMAC_SZ, hmac2.as_slice())?;

    if ct.eq(hmac1_fst, ct_fst, hmacs_out.as_slice())? == 0 {
        return Err("authentication error".to_string());
    }

    // get ciphertext from input buffer and decrypt it
    let buf = Bytes::from_vec(ct.get_slice(ct_fst, ct.len())?.into());
    let pt3 = cipher_decrypt(dec_fn.2, buf, &ckeys[0])?;
    let pt2 = cipher_decrypt(dec_fn.1, pt3, &ckeys[1])?;
    let pt1 = cipher_decrypt(dec_fn.0, pt2, &ckeys[2])?;

    // verify plaintext size
    if ct_fst + V::size() + U::size() + T::size() + pt1.len() != ct.len() {
        return Err("decryption error".to_string());
    }

    Ok(pt1)
}

pub fn generic_triple_encrypt<T, U, V>(
    pt: Bytes,
    k: &Bytes,
    header: &[u8],
    enc_fn: (EncFn<T>, EncFn<U>, EncFn<V>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: AsSlice + Random + Size,
    U: AsSlice + Random + Size,
    V: AsSlice + Random + Size,
{
    if pt.len() < 1 {
        return Err("empty plaintext".to_string());
    }

    if k.len() < 1 {
        return Err("empty key".to_string());
    }

    let header_fst = 0;
    let salt_fst = SALT_FST + header.len();
    let hmac1_fst = HMAC1_FST + header.len();
    let hmac2_fst = HMAC2_FST + header.len();
    let ct_fst = CT_FST + header.len();

    // create output buffer
    let buf_sz = ct_fst + T::size() + U::size() + V::size() + pt.len();
    let mut buf = Bytes::blank(buf_sz);
    buf.copy_from_slice(header_fst, salt_fst, header)?;

    // generate salt and stretch key
    OsRng.fill_bytes(buf.get_mut_slice(salt_fst, hmac1_fst)?);
    let (ckeys, hkeys) = stretch_key(k.as_slice(), buf.get_slice(salt_fst, hmac1_fst)?, 3)?;

    // encrypt plaintext and add it to the output buffer
    let ct1 = cipher_encrypt(enc_fn.0, pt, &ckeys[2])?;
    let ct2 = cipher_encrypt(enc_fn.1, ct1, &ckeys[1])?;
    let ct3 = cipher_encrypt(enc_fn.2, ct2, &ckeys[0])?;

    // calculate hmac and add to output buffer
    let lst = hmac1_fst + ct3.len();
    buf.copy_from_slice(hmac1_fst, lst, ct3.as_slice())?;
    let hmac1 = hmac_fn.0(buf.get_slice(header_fst, lst)?, &hkeys[0])?;
    let hmac2 = hmac_fn.1(buf.get_slice(header_fst, lst)?, &hkeys[1])?;

    // construct output
    buf.copy_from_slice(hmac1_fst, hmac2_fst, hmac1.as_slice())?;
    buf.copy_from_slice(hmac2_fst, ct_fst, hmac2.as_slice())?;
    buf.copy_from_slice(ct_fst, buf_sz, ct3.as_slice())?;

    Ok(buf)
}

fn get_botan_cipher(name: &str) -> Res<botan::Cipher> {
    match Cipher::new(name, CipherDirection::Encrypt) {
        Ok(x) => Ok(x),
        Err(_) => Err(format!("botan cipher {} not found", name)),
    }
}

fn get_openssl_cipher(raw_nid: i32) -> Res<symm::Cipher> {
    match symm::Cipher::from_nid(nid::Nid::from_raw(raw_nid)) {
        Some(x) => Ok(x),
        None => Err(format!("openssl cipher {} not found", raw_nid)),
    }
}

pub fn hmac_keccak(buf: &[u8], k: &Safe48B) -> Res<Safe64B> {
    let mut hmac = Hmac::<sha3::Keccak512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(Safe64B::from_slice(hmac.result().code().as_slice())?)
}

pub fn hmac_sha2(buf: &[u8], k: &Safe48B) -> Res<Safe64B> {
    let mut hmac = Hmac::<sha2::Sha512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(Safe64B::from_slice(hmac.result().code().as_slice())?)
}

pub fn hmac_sha3(buf: &[u8], k: &Safe48B) -> Res<Safe64B> {
    let mut hmac = Hmac::<sha3::Sha3_512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(Safe64B::from_slice(hmac.result().code().as_slice())?)
}

pub fn init() -> Result<(), ()> {
    openssl::init();
    sodiumoxide::init()
}

// stream xor with AES-256-CTR (Rijndael)
pub fn stream_xor_aes256(m: Bytes, iv: &Safe16B, k: &Safe32B) -> Res<Bytes> {
    match symm::encrypt(
        get_openssl_cipher(NIDAES)?,
        k.as_slice(),
        Some(iv.as_slice()),
        m.as_slice(),
    ) {
        Ok(x) => {
            if x.len() != m.len() {
                return Err("aes-256 xor error".to_string());
            }

            Ok(Bytes::from_vec(x))
        }
        Err(e) => {
            e.errors();
            Err("aes-256 xor error".to_string())
        }
    }
}

// stream xor with Camellia-256-CTR
pub fn stream_xor_camellia256(m: Bytes, iv: &Safe16B, k: &Safe32B) -> Res<Bytes> {
    match symm::encrypt(
        get_openssl_cipher(NIDCAM)?,
        k.as_slice(),
        Some(iv.as_slice()),
        m.as_slice(),
    ) {
        Ok(x) => {
            if x.len() != m.len() {
                return Err("camellia-256 xor error".to_string());
            }

            Ok(Bytes::from_vec(x))
        }
        Err(e) => {
            e.errors();
            Err("camellia-256 xor error".to_string())
        }
    }
}

// stream xor with Serpent-256-CTR
pub fn stream_xor_serpent256(m: Bytes, iv: &Safe16B, k: &Safe32B) -> Res<Bytes> {
    let cipher = get_botan_cipher("Serpent/CTR")?;

    if let Err(_) = cipher.set_key(k.as_slice()) {
        return Err("serpent-256 key construction error".to_string());
    }

    match cipher.process(iv.as_slice(), m.as_slice()) {
        Ok(x) => {
            if x.len() != m.len() {
                return Err("serpent-256 xor error".to_string());
            }

            Ok(Bytes::from_vec(x))
        }
        Err(_) => Err("serpent-256 xor error".to_string()),
    }
}

// stream xor with Twofish-256-CTR
pub fn stream_xor_twofish256(m: Bytes, iv: &Safe16B, k: &Safe32B) -> Res<Bytes> {
    let cipher = get_botan_cipher("Twofish/CTR")?;

    if let Err(_) = cipher.set_key(k.as_slice()) {
        return Err("twofish-256 key construction error".to_string());
    }

    match cipher.process(iv.as_slice(), m.as_slice()) {
        Ok(x) => {
            if x.len() != m.len() {
                return Err("twofish-256 xor error".to_string());
            }

            Ok(Bytes::from_vec(x))
        }
        Err(_) => Err("twofish-256 xor error".to_string()),
    }
}

// stream xor with XChaCha20
pub fn stream_xor_xchacha20(m: Bytes, iv: &Safe24B, k: &Safe32B) -> Res<Bytes> {
    let nonce = GenericArray::from_slice(iv.as_slice());
    let key = GenericArray::from_slice(k.as_slice());
    let mut cipher = XChaCha20::new(&key, &nonce);
    let mut xt = m.clone();
    cipher.apply_keystream(xt.as_mut_slice());

    if xt.len() != m.len() {
        return Err("xchacha20 xor error".to_string());
    }

    Ok(xt)
}

// stream xor with XSalsa20
pub fn stream_xor_xsalsa20(m: Bytes, iv: &Safe24B, k: &Safe32B) -> Res<Bytes> {
    let nonce = match xsalsa20::Nonce::from_slice(iv.as_slice()) {
        Some(x) => x,
        None => return Err("xsalsa20 nonce construction error".to_string()),
    };
    let key = match xsalsa20::Key::from_slice(k.as_slice()) {
        Some(x) => x,
        None => return Err("xsalsa20 key construction error".to_string()),
    };
    let xt = Bytes::from_vec(xsalsa20::stream_xor(m.as_slice(), &nonce, &key));

    if xt.len() != m.len() {
        return Err("xsalsa20 xor error".to_string());
    }

    Ok(xt)
}

fn stretch_key(k: &[u8], s: &[u8], n_keys: usize) -> Res<(Vec<Safe32B>, [Safe48B; 2])> {
    // stretch the key with scrypt
    let mut all_keys = Bytes::blank((2 * HMAC_KEY_SZ) + (n_keys * CIPHER_KEY_SZ));

    if let Err(e) = scrypt(
        k,
        s,
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
    let mut fst = 0;
    let mut lst = HMAC_KEY_SZ;
    let hkey1 = Safe48B::from_slice(all_keys.get_slice(fst, lst)?)?;

    fst = lst;
    lst += HMAC_KEY_SZ;
    let hkey2 = Safe48B::from_slice(all_keys.get_slice(fst, lst)?)?;

    let mut ckeys = Vec::<Safe32B>::with_capacity(n_keys);

    for _ in 0..n_keys {
        fst = lst;
        lst += CIPHER_KEY_SZ;
        ckeys.push(Safe32B::from_slice(all_keys.get_slice(fst, lst)?)?);
    }

    Ok((ckeys, [hkey1, hkey2]))
}

#[cfg(test)]
mod unittests {
    mod testutils;

    use super::*;

    #[test]
    fn can_decrypt_with_aes256() {
        let json_str = include_str!("./unittests/aes256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe16B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_aes256(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_aes256() {
        let json_str = include_str!("./unittests/aes256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe16B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_aes256(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_v3_and_c4_ciphertexts_with_triplesec_decrypt() {
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

    #[test]
    fn can_decrypt_with_twofish256() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe16B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_twofish256(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_twofish256() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe16B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_twofish256(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_xchacha20() {
        let json_str = include_str!("./unittests/xchacha20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe24B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_xchacha20(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_xchacha20() {
        let json_str = include_str!("./unittests/xchacha20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe24B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_xchacha20(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe24B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_xsalsa20(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Safe24B::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = Safe32B::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_xsalsa20(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }
}
