// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Everything needed for working with HYGON CSV certificate chains.

pub mod ca;
pub mod csv;
pub mod builtin;
mod chain;

use std::io::{Result};
use serde::{Deserialize, Serialize};

/// An interface for types that may containe entities
/// such as signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

/// Denotes a certificate's usage.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage(u32);

impl Usage {
    /// HYGON Root Key.
    pub const HRK: Usage = Usage(0x0000u32.to_le());

    /// HYGON Signing key.
    pub const HSK: Usage = Usage(0x0013u32.to_le());

    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(0x1001u32.to_le());

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(0x1002u32.to_le());

    /// Platform Diffie-Hellman.
    pub const PDH: Usage = Usage(0x1003u32.to_le());

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(0x1004u32.to_le());
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm(u32);

impl Algorithm {
    pub const SM2_DA: Algorithm = Algorithm(0x0004u32.to_le());
    pub const SM2_DH: Algorithm = Algorithm(0x0005u32.to_le());
}
