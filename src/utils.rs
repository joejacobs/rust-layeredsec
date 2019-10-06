/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use rand::{prelude::RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

pub type Res<T> = Result<T, String>;

// some generic structs for later use
pub trait AsSlice {
    fn as_slice(&self) -> &[u8];
}

pub trait FromSlice
where
    Self: core::marker::Sized,
{
    fn from_slice(b: &[u8]) -> Res<Self>;
}

pub trait Random
where
    Self: core::marker::Sized,
{
    fn random() -> Res<Self>;
}

pub trait Size {
    fn size() -> usize;
}

// macro for defining a fixed size byte array that wipes itself on deletion
#[macro_export]
macro_rules! define_safe_byte_array {
    (
        $name:ident,
        $bytes:expr
    ) => {
        #[derive(Zeroize)]
        #[zeroize(drop)]
        pub struct $name([u8; $bytes]);

        impl AsSlice for $name {
            fn as_slice(&self) -> &[u8] {
                &self.0[..]
            }
        }

        // based on sodiumoxide implementation
        impl FromSlice for $name {
            fn from_slice(b: &[u8]) -> Res<Self> {
                if b.len() != $bytes {
                    return Err("incorrect size".to_string());
                }

                let mut n = $name([0u8; $bytes]);

                for (x, &y) in n.0.iter_mut().zip(b.iter()) {
                    *x = y;
                }

                Ok(n)
            }
        }

        impl Random for $name {
            fn random() -> Res<Self> {
                let mut x = $name([0u8; $bytes]);

                match OsRng.try_fill_bytes(&mut x.0[..]) {
                    Ok(_) => Ok(x),
                    Err(e) => Err(e.to_string()),
                }
            }
        }

        impl Size for $name {
            fn size() -> usize {
                $bytes
            }
        }
    };
}

// safe byte arrays of varying sizes
define_safe_byte_array!(Safe16B, 16);
define_safe_byte_array!(Safe24B, 24);
define_safe_byte_array!(Safe32B, 32);
define_safe_byte_array!(Safe48B, 48);
define_safe_byte_array!(Safe64B, 64);

// a safe byte vector that wipes itself on deletion
#[derive(Clone, Debug, PartialEq, Zeroize)]
#[zeroize(drop)]
pub struct Bytes(Vec<u8>);

impl Bytes {
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
        Bytes(vec![0u8; sz])
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
            Ok(x) => Ok(Bytes(x)),
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
            return Bytes::from_hex(&s[2..]);
        }

        Ok(Bytes(s.to_string().into_bytes()))
    }

    pub fn from_vec(v: Vec<u8>) -> Self {
        Bytes(v)
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
            Ok(_) => Ok(Bytes(v)),
            Err(e) => Err(e.to_string()),
        }
    }
}
