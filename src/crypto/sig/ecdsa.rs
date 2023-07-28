// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

use openssl::{ecdsa, bn};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::{Error, Result};
use crate::util::*;

const SIG_PIECE_SIZE: usize = std::mem::size_of::<[u8; 72]>();

/// The Raw format of ecdsa signature.
#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Signature {
    #[serde(with = "BigArray")]
    r: [u8; 72],
    #[serde(with = "BigArray")]
    s: [u8; 72],
    #[serde(with = "BigArray")]
    _reserved: [u8; 256 - (SIG_PIECE_SIZE) * 2],
}

impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(&value.r)?;
        let s = bn::BigNum::from_le(&value.s)?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

impl  TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}
