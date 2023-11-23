// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

/// CSV certificates interface.
pub mod certs;

/// CSV API interface.
pub mod api;

/// Crypto module for key and signature.
pub(crate) mod crypto;

/// Error module.
pub mod error;

mod util;

pub use util::cached_chain;

use serde::{Deserialize, Serialize};

/// Information about the CSV platform version.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

/// A description of the CSV platform's build information.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Build {
    /// The version information.
    pub version: Version,

    /// The build number.
    pub build: u8,
}

pub struct Body;
