// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Modules for interfacing with CSV Firmware
//! Rust-fridenly API wrappers to communicate the the FFI functions.

/// A handle to the CSV platform.

use std::{
    fs::{File, OpenOptions},
    os::unix::io::{AsRawFd, RawFd},
};
pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
