/* Copyright (c) 2019 Joe Jacobs
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

use super::super::utils::{Bytes, Res};
use serde_json;

#[derive(Debug)]
pub struct TestVector {
    pub pt: Bytes,
    pub key: Bytes,
    pub iv: Option<Bytes>,
    pub ct: Bytes,
}

pub fn parse_test_vectors(json_str: &str) -> Res<Vec<TestVector>> {
    let json: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(x) => x,
        Err(_) => return Err("json parse error".to_string()),
    };

    let mut test_vectors = Vec::<TestVector>::new();

    for v in json.as_array().unwrap() {
        let pt = match v["pt"].as_str() {
            Some(x) => Bytes::from_str(x)?,
            None => return Err("plaintext not found".to_string()),
        };
        let key = match v["key"].as_str() {
            Some(x) => Bytes::from_str(x)?,
            None => return Err("key not found".to_string()),
        };
        let iv = match v["iv"].as_str() {
            Some(x) => Some(Bytes::from_str(x)?),
            None => None,
        };
        let ct = match v["ct"].as_str() {
            Some(x) => Bytes::from_str(x)?,
            None => return Err("ciphertext not found".to_string()),
        };

        test_vectors.push(TestVector { pt, key, iv, ct });
    }

    Ok(test_vectors)
}
