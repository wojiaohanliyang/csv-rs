// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use openssl::error::ErrorStack;
use std::{
    convert::From,
    error,
    fmt::{Debug, Display},
    io,
};

/// Error conditions returned by the CSV platform or by layers above it
/// (i.e., the Linux kernel).
///
/// These error conditions are documented in the HYGON CSV API spec, but
/// their documentation has been copied here for completeness.
#[derive(Debug)]
#[repr(u32)]
pub enum Error {
    /// Something went wrong when communicating with
    /// kernel or CSV platform
    IoError(io::Error),

    /// The provided signature is invalid.
    BadSignature,

    /// Unknown error
    Unknown,
}

/// There are a number of error conditions that can occur between this
/// layer all the way down to the CSV platform. Most of these cases have
/// been enumerated; however, there is a possibility that some error
/// conditions are not encapsulated here.
#[derive(Debug)]
pub enum Indeterminate<T: Debug> {
    /// The error condition is known.
    Known(T),

    /// The error condition is unknown.
    Unknown,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Error::IoError(_) => "I/O Error",
            Error::BadSignature => "Provided signature is invalid",
            Error::Unknown => "Unknown Error",
        };
        write!(f, "{err_description}")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<ErrorStack> for Error {
    #[inline]
    fn from(error: ErrorStack) -> Error {
        Error::IoError(io::Error::from(error))
    }
}

impl error::Error for Indeterminate<Error> {}

impl Display for Indeterminate<Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Indeterminate::Known(error) => format!("Known Error: {error}"),
            Indeterminate::Unknown => "Unknown Error Encountered".to_string(),
        };

        write!(f, "{err_description}")
    }
}

impl From<io::Error> for Indeterminate<Error> {
    #[inline]
    fn from(error: io::Error) -> Indeterminate<Error> {
        Indeterminate::Known(error.into())
    }
}

impl From<Indeterminate<Error>> for io::Error {
    #[inline]
    fn from(indeterminate: Indeterminate<Error>) -> io::Error {
        match indeterminate {
            Indeterminate::Known(e) => io::Error::new(io::ErrorKind::Other, e),
            Indeterminate::Unknown => io::Error::new(io::ErrorKind::Other, "unknown CSV error"),
        }
    }
}
