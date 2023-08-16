// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Operations that can be done on a Certificate Authority chain.

use crate::{
    certs::{Verifiable, Usage, Algorithm},
    crypto::{PublicKey, key::ecc, sig::ecdsa, Signature},
    util::*,
};

use std::io::{Error, Result, Write, Read};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Data {
    pub kid: [u8; 16],
    pub sid: [u8; 16],
    pub usage: Usage,
    pub reserved: [u8; 24],
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Preamble {
    pub ver: u32,
    pub data: Data,
}

#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Body {
    pub preamble: Preamble,
    pub pubkey: ecc::PubKey,
    pub uid_size: u16,
    #[serde(with = "BigArray")]
    pub user_id: [u8; 254],
    #[serde(with = "BigArray")]
    pub reserved: [u8; 108],
}

/// A Certificate Authority chain.
#[repr(C)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct  Certificate {
    pub body: Body,
    signature: ecdsa::Signature,
    #[serde(with = "BigArray")]
    _reserved: [u8; 112],
}

impl TryFrom<&Certificate> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &Certificate) -> Result<Self> {
        let sig = Vec::try_from(&value.signature)?;
        Ok(Self {
            sig,
            id: Some(value.body.preamble.data.sid),
            usage: Usage::HRK.into(),
            algo: None,
        })
    }
}

impl TryFrom<&Certificate> for PublicKey {
    type Error = Error;

    #[inline]
    fn try_from(value: &Certificate) -> Result<Self> {
        let key = value.body.pubkey;
        Ok(Self {
            id: Some(value.body.preamble.data.kid),
            key,
            usage: value.body.preamble.data.usage,
            algo: Some(Algorithm::SM2_DA.into()),
        })
    }
}

impl codicon::Decoder<()> for Certificate {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        Ok(Self {
            body: reader.load()?,
            signature: reader.load()?,
            _reserved: reader.load()?,
        })
    }
}

impl codicon::Encoder<crate::Body> for Certificate {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<()> {
        writer.save(&self.body)
    }
}

impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey = self.0.try_into()?;
        let sig: Signature = self.1.try_into()?;
        key.verify(self.1, &self.0.body.user_id[..self.0.body.uid_size as usize], &sig)
    }
}
