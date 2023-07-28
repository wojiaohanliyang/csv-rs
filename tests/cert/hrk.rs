// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use csv_rs::certs::{ca, builtin::HRK, Verifiable};
use codicon::Decoder;

#[test]
fn verify() {
    let hrk = ca::Certificate::decode(&mut &HRK[..], ()).unwrap();
    (&hrk, &hrk).verify().unwrap();
}
