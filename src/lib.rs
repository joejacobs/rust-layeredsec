/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

mod utils;

pub use self::utils::Bytes;
use self::utils::*;
use botan::{Cipher, CipherDirection};
use hmac::{Hmac, Mac};
use openssl::{nid, pkcs5::scrypt, symm};
use sha2;
use sha3;
use sodiumoxide::crypto::stream::{xchacha20, xsalsa20};
use sodiumoxide::{randombytes::randombytes_into, utils::memcmp};
use zeroize::Zeroize;

const CIPHER_KEY_SZ: usize = 32;
const HMAC_KEY_SZ: usize = 48;
const HMAC_SZ: usize = 64;
const SALT_SZ: usize = 16;

// init vector sizes for different ciphers
const XC20_IV_SZ: usize = 24;
const XS20_IV_SZ: usize = 24;
const AES_IV_SZ: usize = 16;
const CAM_IV_SZ: usize = 16;
const SP_IV_SZ: usize = 16;
const TF_IV_SZ: usize = 16;

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

// abbreviations of common types for convenience
type EncFn<T> = fn(Bytes, &T, &CipherKey) -> Res<Bytes>;
type DecFn<T> = fn(Bytes, &T, &CipherKey) -> Res<Bytes>;
type HmacFn = fn(&[u8], &HmacKey) -> Res<HmacBuf>;

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

            pub fn decrypt(ct: Bytes, k: Bytes) -> Result<Bytes, String> {
                generic_double_decrypt(ct, k, $header, ($cipher1, $cipher2), ($hmac1, $hmac2))
            }

            pub fn encrypt(pt: Bytes, k: Bytes) -> Result<Bytes, String> {
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

            pub fn decrypt(ct: Bytes, k: Bytes) -> Result<Bytes, String> {
                generic_triple_decrypt(
                    ct,
                    k,
                    $header,
                    ($cipher1, $cipher2, $cipher3),
                    ($hmac1, $hmac2),
                )
            }

            pub fn encrypt(pt: Bytes, k: Bytes) -> Result<Bytes, String> {
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

// key byte arrays
define_safe_byte_arr!(CipherKey, CIPHER_KEY_SZ);
define_safe_byte_arr!(HmacKey, HMAC_KEY_SZ);
define_safe_byte_arr!(HmacBuf, HMAC_SZ);

// iv byte arrays
define_safe_byte_arr!(Xc20Iv, XC20_IV_SZ);
define_safe_byte_arr!(Xs20Iv, XS20_IV_SZ);
define_safe_byte_arr!(AesIv, AES_IV_SZ);
define_safe_byte_arr!(CamIv, CAM_IV_SZ);
define_safe_byte_arr!(SpIv, SP_IV_SZ);
define_safe_byte_arr!(TfIv, TF_IV_SZ);

// define triplesec module
pub mod triplesec {
    use super::*;

    define_2_layer_encryption_module!(
        v4,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x4],
        stream_xor_xsalsa20,
        stream_xor_aes256,
        hmac_sha2,
        hmac_sha3
    );

    define_3_layer_encryption_module!(
        v3,
        &[0x1c, 0x94, 0xd7, 0xde, 0x0, 0x0, 0x0, 0x3],
        stream_xor_xsalsa20,
        stream_xor_twofish256,
        stream_xor_aes256,
        hmac_sha2,
        hmac_keccak
    );

    pub fn decrypt(ct: Bytes, k: Bytes) -> Res<Bytes> {
        if ct.len() < CT_FST + 9 {
            return Err("ciphertext is too short".to_string());
        }

        if !memcmp(ct.get_slice(0, 4)?, &[0x1c, 0x94, 0xd7, 0xde]) {
            return Err("magic number error".to_string());
        }

        if memcmp(ct.get_slice(4, 8)?, &[0x0, 0x0, 0x0, 0x3]) {
            v3::decrypt(ct, k)
        } else if memcmp(ct.get_slice(4, 8)?, &[0x0, 0x0, 0x0, 0x4]) {
            v4::decrypt(ct, k)
        } else {
            Err("unsupported triplesec version".to_string())
        }
    }

    pub fn encrypt(pt: Bytes, k: Bytes) -> Res<Bytes> {
        v4::encrypt(pt, k)
    }
}

fn cipher_decrypt<T>(dec_fn: DecFn<T>, buf: Bytes, k: &CipherKey) -> Res<Bytes>
where
    T: FromSlice<T> + Size,
{
    let ct_sz = buf.len() - T::size();
    let iv = T::from_slice(buf.get_slice(0, T::size())?)?;
    let mut ct = Bytes::blank(ct_sz);
    ct.copy_from_slice(0, ct_sz, buf.get_slice(T::size(), buf.len())?)?;
    dec_fn(ct, &iv, k)
}

fn cipher_encrypt<T>(enc_fn: EncFn<T>, pt: Bytes, k: &CipherKey) -> Res<Bytes>
where
    T: AsSlice + Random<T> + Size,
{
    let buf_sz = T::size() + pt.len();
    let iv = T::random();
    let ct = enc_fn(pt, &iv, k)?;

    let mut buf = Bytes::blank(buf_sz);
    buf.copy_from_slice(0, T::size(), iv.as_slice())?;
    buf.copy_from_slice(T::size(), buf_sz, ct.as_slice())?;
    Ok(buf)
}

pub fn generic_double_decrypt<T, U>(
    ct: Bytes,
    k: Bytes,
    header: &[u8],
    dec_fn: (DecFn<T>, DecFn<U>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: FromSlice<T> + Size,
    U: FromSlice<U> + Size,
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

    if salt_fst > 0 && !memcmp(ct.get_slice(header_fst, salt_fst)?, header) {
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
    let hmacs_in = ct.get_slice(hmac1_fst, ct_fst)?;

    if !memcmp(hmacs_in, hmacs_out.as_slice()) {
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
    k: Bytes,
    header: &[u8],
    enc_fn: (EncFn<T>, EncFn<U>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: AsSlice + Random<T> + Size,
    U: AsSlice + Random<U> + Size,
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
    randombytes_into(buf.get_mut_slice(salt_fst, hmac1_fst)?);
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
    k: Bytes,
    header: &[u8],
    dec_fn: (DecFn<T>, DecFn<U>, DecFn<V>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: FromSlice<T> + Size,
    U: FromSlice<U> + Size,
    V: FromSlice<V> + Size,
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

    if salt_fst > 0 && !memcmp(ct.get_slice(header_fst, salt_fst)?, header) {
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
    let hmacs_in = ct.get_slice(hmac1_fst, ct_fst)?;

    if !memcmp(hmacs_in, hmacs_out.as_slice()) {
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
    k: Bytes,
    header: &[u8],
    enc_fn: (EncFn<T>, EncFn<U>, EncFn<V>),
    hmac_fn: (HmacFn, HmacFn),
) -> Res<Bytes>
where
    T: AsSlice + Random<T> + Size,
    U: AsSlice + Random<U> + Size,
    V: AsSlice + Random<V> + Size,
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
    randombytes_into(buf.get_mut_slice(salt_fst, hmac1_fst)?);
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

pub fn hmac_keccak(buf: &[u8], k: &HmacKey) -> Res<HmacBuf> {
    let mut hmac = Hmac::<sha3::Keccak512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(HmacBuf::from_slice(hmac.result().code().as_slice())?)
}

pub fn hmac_sha2(buf: &[u8], k: &HmacKey) -> Res<HmacBuf> {
    let mut hmac = Hmac::<sha2::Sha512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(HmacBuf::from_slice(hmac.result().code().as_slice())?)
}

pub fn hmac_sha3(buf: &[u8], k: &HmacKey) -> Res<HmacBuf> {
    let mut hmac = Hmac::<sha3::Sha3_512>::new_varkey(k.as_slice()).unwrap();
    hmac.input(buf);
    Ok(HmacBuf::from_slice(hmac.result().code().as_slice())?)
}

pub fn init() -> Result<(), ()> {
    openssl::init();
    sodiumoxide::init()
}

// stream xor with AES-256-CTR (Rijndael)
pub fn stream_xor_aes256(m: Bytes, iv: &AesIv, k: &CipherKey) -> Res<Bytes> {
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
pub fn stream_xor_camellia256(m: Bytes, iv: &CamIv, k: &CipherKey) -> Res<Bytes> {
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
pub fn stream_xor_serpent256(m: Bytes, iv: &SpIv, k: &CipherKey) -> Res<Bytes> {
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
pub fn stream_xor_twofish256(m: Bytes, iv: &TfIv, k: &CipherKey) -> Res<Bytes> {
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
pub fn stream_xor_xchacha20(m: Bytes, iv: &Xc20Iv, k: &CipherKey) -> Res<Bytes> {
    let nonce = match xchacha20::Nonce::from_slice(iv.as_slice()) {
        Some(x) => x,
        None => return Err("xchacha20 nonce construction error".to_string()),
    };
    let key = match xchacha20::Key::from_slice(k.as_slice()) {
        Some(x) => x,
        None => return Err("xchacha20 key construction error".to_string()),
    };
    let xt = Bytes::from_vec(xchacha20::stream_xor(m.as_slice(), &nonce, &key));

    if xt.len() != m.len() {
        return Err("xchacha20 xor error".to_string());
    }

    Ok(xt)
}

// stream xor with XSalsa20
pub fn stream_xor_xsalsa20(m: Bytes, iv: &Xs20Iv, k: &CipherKey) -> Res<Bytes> {
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

fn stretch_key(k: &[u8], s: &[u8], n_keys: usize) -> Res<(Vec<CipherKey>, [HmacKey; 2])> {
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
    let hkey1 = HmacKey::from_slice(all_keys.get_slice(fst, lst)?)?;

    fst = lst;
    lst += HMAC_KEY_SZ;
    let hkey2 = HmacKey::from_slice(all_keys.get_slice(fst, lst)?)?;

    let mut ckeys = Vec::<CipherKey>::new();

    for _ in 0..n_keys {
        fst = lst;
        lst += CIPHER_KEY_SZ;
        ckeys.push(CipherKey::from_slice(all_keys.get_slice(fst, lst)?)?);
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
            let iv = AesIv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_aes256(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_aes256() {
        let json_str = include_str!("./unittests/aes256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = AesIv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
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
            let pt = triplesec::decrypt(v.ct, v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_decrypt_with_triplesec_v3() {
        let json_str = include_str!("./unittests/triplesec-v3-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let pt = triplesec::v3::decrypt(v.ct, v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_decrypt_with_triplesec_v4() {
        let json_str = include_str!("./unittests/triplesec-v4-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let pt = triplesec::v4::decrypt(v.ct, v.key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_decrypt_with_twofish256() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = TfIv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_twofish256(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_twofish256() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = TfIv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_twofish256(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Xs20Iv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
            let pt = stream_xor_xsalsa20(v.ct, &iv, &key).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let iv = Xs20Iv::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = CipherKey::from_slice(v.key.as_slice()).unwrap();
            let ct = stream_xor_xsalsa20(v.pt, &iv, &key).unwrap();
            assert_eq!(v.ct, ct);
        }
    }
}
