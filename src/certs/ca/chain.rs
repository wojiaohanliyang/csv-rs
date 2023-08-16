// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! For operating on Certificate Authority chains.

use crate::certs::ca::cert::Certificate;

/// A complete Certificate Authority chain.
#[repr(C)]
pub struct Chain {
    /// The HYGON Sighing Key certificate.
    pub hsk: Certificate,

    /// The HYGON Root Key certificate.
    pub hrk: Certificate,
}


