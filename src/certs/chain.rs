// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Utilities for operating on entire certificate chains.

use crate::certs::ca;
use crate::certs::csv;

/// A complete certificate chain.
#[repr(C)]
#[allow(dead_code)]
pub struct Chain {
    /// The Certificate Authority chain
    pub ca: ca::Chain,

    /// The CSV platform chain.
    pub csv: csv::Chain,
}
