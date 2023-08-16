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

use serde::{Deserialize, Serialize};

/// Information about the CSV platform version.
#[repr(C)]
#[derive(Debug, Copy, Clone, Deserialize, Serialize)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor:u8,
}

pub struct Body;
