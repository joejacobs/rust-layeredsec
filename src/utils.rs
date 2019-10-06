/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use rand::{prelude::RngCore, rngs::OsRng};
use stream_cipher::generic_array::{ArrayLength, GenericArray};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub type Res<T> = Result<T, String>;

#[derive(Zeroize)]
pub struct ByteArr<N: ArrayLength<u8>>(GenericArray<u8, N>);

impl<N: ArrayLength<u8>> ByteArr<N> {
    pub fn as_generic_array(&self) -> &GenericArray<u8, N> {
        &self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn from_generic_array(x: GenericArray<u8, N>) -> Self {
        Self(x)
    }

    pub fn from_slice(b: &[u8]) -> Res<Self> {
        Ok(Self(GenericArray::clone_from_slice(b)))
    }

    pub fn random() -> Res<Self> {
        let mut x = Self(GenericArray::default());

        match OsRng.try_fill_bytes(x.0.as_mut_slice()) {
            Ok(_) => Ok(x),
            Err(e) => Err(e.to_string()),
        }
    }
}

impl<N: ArrayLength<u8>> Drop for ByteArr<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// a safe byte vector that wipes itself on deletion
#[derive(Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct ByteVec(Vec<u8>);

impl ByteVec {
    pub fn as_hex(&self) -> Res<String> {
        match botan::hex_encode(self.as_slice()) {
            Ok(x) => Ok(x),
            Err(_) => Err("hex encode error".to_string()),
        }
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }

    pub fn blank(sz: usize) -> Self {
        ByteVec(vec![0u8; sz])
    }

    pub fn copy_from_slice(&mut self, x: usize, y: usize, b: &[u8]) -> Res<()> {
        if b.len() < 1 {
            if y - x == 0 {
                return Ok(());
            }

            return Err("empty slice".to_string());
        }

        if y > self.0.len() || x >= y {
            return Err("index out of bounds".to_string());
        }

        if y - x != b.len() {
            return Err("incorrect slice size".to_string());
        }

        self.0[x..y].copy_from_slice(b);
        Ok(())
    }

    pub fn eq(&self, a: usize, b: usize, rhs: &[u8]) -> Res<u8> {
        if b > self.0.len() || a >= b {
            return Err("index out of bounds".to_string());
        }

        Ok(self.0[a..b].ct_eq(rhs).unwrap_u8())
    }

    pub fn from_hex(hex: &str) -> Res<Self> {
        match botan::hex_decode(hex) {
            Ok(x) => Ok(ByteVec(x)),
            Err(_) => Err("hex decode error".to_string()),
        }
    }

    pub fn from_slice(b: &[u8]) -> Res<Self> {
        let mut v = Self::blank(b.len());
        v.copy_from_slice(0, b.len(), b)?;
        Ok(v)
    }

    pub fn from_str(s: &str) -> Res<Self> {
        if s.find("0x") == Some(0) {
            return ByteVec::from_hex(&s[2..]);
        }

        Ok(ByteVec(s.to_string().into_bytes()))
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        ByteVec(v)
    }

    pub fn get_mut_slice(&mut self, x: usize, y: usize) -> Res<&mut [u8]> {
        if y > self.0.len() || x >= y {
            return Err("index out of bounds".to_string());
        }

        Ok(&mut self.0[x..y])
    }

    pub fn get_slice(&self, a: usize, b: usize) -> Res<&[u8]> {
        if b > self.0.len() || a >= b {
            return Err("index out of bounds".to_string());
        }

        Ok(&self.0[a..b])
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn random(sz: usize) -> Res<Self> {
        let mut v = vec![0u8; sz];

        match OsRng.try_fill_bytes(&mut v[..]) {
            Ok(_) => Ok(ByteVec(v)),
            Err(e) => Err(e.to_string()),
        }
    }
}

#[cfg(test)]
pub(crate) mod testutils {
    use super::{ByteVec, Res};

    use serde_json;

    #[derive(Debug)]
    pub struct TestVector {
        pub pt: ByteVec,
        pub key: ByteVec,
        pub iv: Option<ByteVec>,
        pub ct: ByteVec,
    }

    pub fn parse_test_vectors(json_str: &str) -> Res<Vec<TestVector>> {
        let json: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(x) => x,
            Err(_) => return Err("json parse error".to_string()),
        };

        let mut test_vectors = Vec::<TestVector>::new();

        for v in json.as_array().unwrap() {
            let pt = match v["pt"].as_str() {
                Some(x) => ByteVec::from_str(x)?,
                None => return Err("plaintext not found".to_string()),
            };
            let key = match v["key"].as_str() {
                Some(x) => ByteVec::from_str(x)?,
                None => return Err("key not found".to_string()),
            };
            let iv = match v["iv"].as_str() {
                Some(x) => Some(ByteVec::from_str(x)?),
                None => None,
            };
            let ct = match v["ct"].as_str() {
                Some(x) => ByteVec::from_str(x)?,
                None => return Err("ciphertext not found".to_string()),
            };

            test_vectors.push(TestVector { pt, key, iv, ct });
        }

        Ok(test_vectors)
    }
}
