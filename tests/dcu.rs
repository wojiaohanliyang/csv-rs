// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use csv_rs::api::dcu::*;
//use crate::certs::csv;

#[cfg_attr(not(has_dev_dcu), ignore)]
#[test_log::test]
fn get_report() {
    let mnonce: [u8; 16] = [
        112, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
    ];

    let mut dcu_device: DcuDevice = DcuDevice::new().unwrap();

    let reports = dcu_device.get_report(mnonce).unwrap();

    for report in &reports {
        assert_eq!(mnonce, report.body.mnonce);
    }
}

#[cfg_attr(not(has_dev_dcu), ignore)]
#[cfg(feature = "network")]
#[tokio::test]
async fn get_report_and_verify() {
    let mnonce: [u8; 16] = [
        112, 233, 62, 161, 65, 225, 252, 103, 62, 1, 126, 151, 234, 220, 107, 150,
    ];
    let mut dcu_device = DcuDevice::new().unwrap();

    let reports = dcu_device.get_report(mnonce).unwrap();

    verify_reports(&reports, &mnonce).await.unwrap();
}
