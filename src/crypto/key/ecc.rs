// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Interfaces for ecc keys.

use openssl::{ec, bn, pkey};
use crate::{
    crypto::key::group::Group,
    util::*,
};
use std::io::{Error, Result};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// The Raw format of ecc pubkey.
#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct PubKey {
    pub g: Group,
    #[serde(with = "BigArray")]
    pub x: [u8; 72],
    #[serde(with = "BigArray")]
    pub y: [u8; 72],
}

impl TryFrom<&PubKey> for ec::EcKey<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        let s = value.g.size()?;
        Ok(ec::EcKey::from_public_key_affine_coordinates(
            &*ec::EcGroup::try_from(value.g)?,
            &*bn::BigNum::from_le(&value.x[..s])?,
            &*bn::BigNum::from_le(&value.y[..s])?,
        )?)
    }
}
