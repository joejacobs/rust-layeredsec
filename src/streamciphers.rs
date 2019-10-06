use super::utils::*;

use aes::Aes256 as RustCryptoAes256;
use chacha20::XChaCha20 as RustCryptoXChaCha20;
use ctr::Ctr128 as RustCryptoCtr128;
use salsa20::XSalsa20 as RustCryptoXSalsa20;
use stream_cipher::{
    generic_array::{
        typenum::{U16, U24, U32},
        ArrayLength,
    },
    NewStreamCipher, SyncStreamCipher,
};

const NID_CAMELLIA: i32 = 971;

type RustCryptoAes256Ctr = RustCryptoCtr128<RustCryptoAes256>;

// traits required for all ciphers
pub trait StreamCipher {
    type KeySize: ArrayLength<u8>;
    type NonceSize: ArrayLength<u8>;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec>;

    fn nonce_size(&self) -> usize;
}

// AES-256 (Rijndael) in CTR mode
pub struct Aes256Ctr();

impl StreamCipher for Aes256Ctr {
    type KeySize = U32;
    type NonceSize = U16;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        let mut cipher = RustCryptoAes256Ctr::new(key.as_generic_array(), nonce.as_generic_array());
        apply_keystream_rustcrypto(&mut cipher, m)
    }

    fn nonce_size(&self) -> usize {
        16
    }
}

// Camellia-256 in CTR mode
pub struct Camellia256Ctr();

impl StreamCipher for Camellia256Ctr {
    type KeySize = U32;
    type NonceSize = U16;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        match openssl::symm::encrypt(
            get_openssl_cipher(NID_CAMELLIA)?,
            key.as_slice(),
            Some(nonce.as_slice()),
            m.as_slice(),
        ) {
            Ok(x) => {
                if x.len() != m.len() {
                    return Err("incorrect message length".to_string());
                }

                Ok(ByteVec::from_vec(x))
            }
            Err(e) => {
                e.errors();
                Err("encrypt error".to_string())
            }
        }
    }

    fn nonce_size(&self) -> usize {
        16
    }
}

// Serpent-256 in CTR mode
pub struct Serpent256Ctr();

impl StreamCipher for Serpent256Ctr {
    type KeySize = U32;
    type NonceSize = U16;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        let cipher = get_botan_cipher("Serpent/CTR")?;
        apply_keystream_botan(cipher, m, key, nonce)
    }

    fn nonce_size(&self) -> usize {
        16
    }
}

// Twofish-256 in CTR mode
pub struct Twofish256Ctr();

impl StreamCipher for Twofish256Ctr {
    type KeySize = U32;
    type NonceSize = U16;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        let cipher = get_botan_cipher("Twofish/CTR")?;
        apply_keystream_botan(cipher, m, key, nonce)
    }

    fn nonce_size(&self) -> usize {
        16
    }
}

// XChaCha20
pub struct XChaCha20();

impl StreamCipher for XChaCha20 {
    type KeySize = U32;
    type NonceSize = U24;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        let mut cipher = RustCryptoXChaCha20::new(key.as_generic_array(), nonce.as_generic_array());
        apply_keystream_rustcrypto(&mut cipher, m)
    }

    fn nonce_size(&self) -> usize {
        24
    }
}

// XSalsa20
pub struct XSalsa20();

impl StreamCipher for XSalsa20 {
    type KeySize = U32;
    type NonceSize = U24;

    fn apply_keystream(
        &self,
        m: ByteVec,
        key: &ByteArr<Self::KeySize>,
        nonce: &ByteArr<Self::NonceSize>,
    ) -> Res<ByteVec> {
        let mut cipher = RustCryptoXSalsa20::new(key.as_generic_array(), nonce.as_generic_array());
        apply_keystream_rustcrypto(&mut cipher, m)
    }

    fn nonce_size(&self) -> usize {
        24
    }
}

// apply a botan stream cipher to a message
#[inline]
fn apply_keystream_botan<M, N>(
    cipher: botan::Cipher,
    m: ByteVec,
    key: &ByteArr<M>,
    nonce: &ByteArr<N>,
) -> Res<ByteVec>
where
    M: ArrayLength<u8>,
    N: ArrayLength<u8>,
{
    if let Err(_) = cipher.set_key(key.as_slice()) {
        return Err("key error".to_string());
    }

    match cipher.process(nonce.as_slice(), m.as_slice()) {
        Ok(x) => {
            if x.len() != m.len() {
                return Err("incorrect message length".to_string());
            }

            Ok(ByteVec::from_vec(x))
        }
        Err(_) => Err("process error".to_string()),
    }
}

// apply a rustcrypto stream cipher to a message
#[inline]
fn apply_keystream_rustcrypto<T: SyncStreamCipher>(cipher: &mut T, m: ByteVec) -> Res<ByteVec> {
    let mut xt = m.clone();
    cipher.apply_keystream(xt.as_mut_slice());

    if xt.len() != m.len() {
        return Err("incorrect message length".to_string());
    }

    Ok(xt)
}

// get a botan cipher
#[inline]
fn get_botan_cipher(name: &str) -> Res<botan::Cipher> {
    match botan::Cipher::new(name, botan::CipherDirection::Encrypt) {
        Ok(x) => Ok(x),
        Err(_) => Err(format!("botan cipher {} not found", name)),
    }
}

// get an openssl cipher
#[inline]
fn get_openssl_cipher(raw_nid: i32) -> Res<openssl::symm::Cipher> {
    match openssl::symm::Cipher::from_nid(openssl::nid::Nid::from_raw(raw_nid)) {
        Some(x) => Ok(x),
        None => Err(format!("openssl cipher {} not found", raw_nid)),
    }
}

#[cfg(test)]
mod tests {
    use super::super::utils::testutils;
    use super::*;

    #[test]
    fn can_decrypt_with_aes256ctr() {
        let json_str = include_str!("./unittests/aes256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let pt = Aes256Ctr().apply_keystream(v.ct, &key, &nonce).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_aes256ctr() {
        let json_str = include_str!("./unittests/aes256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let ct = Aes256Ctr().apply_keystream(v.pt, &key, &nonce).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_twofish256ctr() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let pt = Twofish256Ctr().apply_keystream(v.ct, &key, &nonce).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_twofish256ctr() {
        let json_str = include_str!("./unittests/twofish256-ctr-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let ct = Twofish256Ctr().apply_keystream(v.pt, &key, &nonce).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_xchacha20() {
        let json_str = include_str!("./unittests/xchacha20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let pt = XChaCha20().apply_keystream(v.ct, &key, &nonce).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_xchacha20() {
        let json_str = include_str!("./unittests/xchacha20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let ct = XChaCha20().apply_keystream(v.pt, &key, &nonce).unwrap();
            assert_eq!(v.ct, ct);
        }
    }

    #[test]
    fn can_decrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let pt = XSalsa20().apply_keystream(v.ct, &key, &nonce).unwrap();
            assert_eq!(v.pt, pt);
        }
    }

    #[test]
    fn can_encrypt_with_xsalsa20() {
        let json_str = include_str!("./unittests/xsalsa20-tests.json");
        let test_vectors = testutils::parse_test_vectors(json_str).unwrap();

        for v in test_vectors {
            let nonce = ByteArr::from_slice(v.iv.unwrap().as_slice()).unwrap();
            let key = ByteArr::from_slice(v.key.as_slice()).unwrap();
            let ct = XSalsa20().apply_keystream(v.pt, &key, &nonce).unwrap();
            assert_eq!(v.ct, ct);
        }
    }
}
