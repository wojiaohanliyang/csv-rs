// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Operations that can be done on a CSV certificate.

use crate::{
    certs::{ca, Algorithm, Usage, Verifiable},
    crypto::{key::ecc, sig::ecdsa, PublicKey, Signature},
    util::*,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::{Error, ErrorKind, Read, Result, Write};

#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Pubkey {
    pub usage: Usage,
    pub algo: Algorithm,
    pub key: ecc::PubKey,
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Data {
    pub firmware: crate::Version,
    pub reserved1: u16,
    pub pubkey: Pubkey,
    pub uid_size: u16,
    #[serde(with = "BigArray")]
    pub user_id: [u8; 254],
    pub sid: [u8; 16],
    #[serde(with = "BigArray")]
    pub reserved2: [u8; 608],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Body {
    pub ver: u32,
    pub data: Data,
}

#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Signatures {
    usage: Usage,
    algo: Algorithm,
    signature: ecdsa::Signature,
    #[serde(with = "BigArray")]
    _reserved: [u8; 368],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Certificate {
    pub body: Body,
    pub sigs: [Signatures; 2],
}

impl TryFrom<&Signatures> for Option<Signature> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signatures) -> Result<Self> {
        if value.is_empty() {
            return Ok(None);
        }

        let usage = value.usage;
        let algo = value.algo;
        let sig = Vec::try_from(&value.signature)?;
        Ok(Some(Signature {
            sig,
            usage,
            algo: Some(algo),
            id: None,
        }))
    }
}

impl TryFrom<&Certificate> for [Option<Signature>; 2] {
    type Error = Error;

    #[inline]
    fn try_from(value: &Certificate) -> Result<Self> {
        Ok([(&value.sigs[0]).try_into()?, (&value.sigs[1]).try_into()?])
    }
}

impl TryFrom<&Certificate> for PublicKey {
    type Error = Error;

    fn try_from(value: &Certificate) -> Result<Self> {
        let key = value.body.data.pubkey.key;
        Ok(Self {
            id: None,
            key,
            usage: value.body.data.pubkey.usage,
            algo: Some(value.body.data.pubkey.algo),
        })
    }
}

impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey = self.0.try_into()?;

        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key
                .verify(
                    self.1,
                    &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
                    sig,
                )
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(ErrorKind::InvalidInput.into())
    }
}

impl Verifiable for (&ca::cert::Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<()> {
        let key: PublicKey = self.0.try_into()?;
        let sigs: [Option<Signature>; 2] = self.1.try_into()?;
        for sig in sigs.iter().flatten() {
            if key
                .verify(
                    self.1,
                    &self.0.body.user_id[..self.0.body.uid_size as usize],
                    sig,
                )
                .is_ok()
            {
                return Ok(());
            }
        }
        Err(ErrorKind::InvalidInput.into())
    }
}

impl codicon::Decoder<()> for Signatures {
    type Error = Error;

    #[inline]
    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let mut _reserved = [0u8; 368];
        let usage: Usage = reader.load()?;
        let algo: Algorithm = reader.load()?;
        let signature: ecdsa::Signature = reader.load()?;
        reader.read_exact(&mut _reserved)?;
        Ok(Self {
            usage,
            algo,
            signature,
            _reserved,
        })
    }
}

impl codicon::Decoder<()> for Certificate {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let body: Body = reader.load()?;
        let sig1 = Signatures::decode(&mut reader, ())?;
        let sig2 = Signatures::decode(&mut reader, ())?;
        Ok(Self {
            body,
            sigs: [sig1, sig2],
        })
    }
}

impl codicon::Encoder<crate::Body> for Certificate {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<()> {
        writer.save(&self.body)
    }
}

impl Signatures {
    pub fn is_empty(&self) -> bool {
        match self.usage {
            Usage::CEK | Usage::HRK | Usage::HSK | Usage::OCA | Usage::PDH | Usage::PEK => {
                !matches!(self.algo, Algorithm::SM2_DA | Algorithm::SM2_DH)
            }
            _ => true,
        }
    }
}
