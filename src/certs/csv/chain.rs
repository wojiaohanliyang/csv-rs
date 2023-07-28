// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! For operating on the CSV platform certificate chain.

use super::cert::Certificate;

/// The CSV certificate chain.
#[repr(C)]
pub struct Chain {
    /// The Platform Diffie-Hellman certificate
    pub pdh: Certificate,

    /// The certificate for the PEK.
    pub pek: Certificate,

    /// The certificate for the OCA.
    pub oca: Certificate,

    /// The certificate for the CEK.
    pub cek: Certificate,
}
