// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::path::Path;

fn main() {
    if cfg!(feature = "hw_tests") || Path::new("/dev/csv-guest").exists() {
        println!("cargo:rustc-cfg=has_dev_csv_guest");
    }
}
