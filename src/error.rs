
// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::io;
use openssl::error::ErrorStack;

#[derive(Debug)]
pub enum Error {
    /// Something went wrong when communicating with 
    /// kernel or CSV platform
    IoError(io::Error),

    /// The provided signature is invalid.
    BadSignature,

    /// Unknown error
    Unknown,
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<ErrorStack> for Error {
    #[inline]
    fn from(error:ErrorStack) -> Error {
        Error::IoError(io::Error::from(error))
    }
}
