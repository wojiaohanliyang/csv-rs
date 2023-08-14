// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::error::*;
mod ioctl;
pub use ioctl::*;
mod types;
pub use types::*;
use std::fs::{File, OpenOptions};

/// A handle to the CSV guest device.
pub struct CsvGuest(File);

impl CsvGuest {
    /// Generate a handle to the CSV guest platform via `/dev/csv-guest`.
    pub fn open() -> std::io::Result<CsvGuest> {
        let file = OpenOptions::new()
            .read(true)
            .open("/dev/csv-guest")?;
        Ok(CsvGuest(file))
    }

    /// Requests an attestation report from the HYGON Secure Processor.
    pub fn get_report(
        &mut self,
        data: Option<[u8; 64]>,
        mnonce: [u8; 16],
    ) -> Result<(AttestationReport, ReportSigner), Error> {
        let report_request = ReportReq::new(data, mnonce)?;

        let mut report_response = ReportRsp::default();

        // Convert ReportReq to bytes
        let request_bytes: &[u8] = unsafe {
            let req_ptr = &report_request as *const ReportReq as *const u8;
            std::slice::from_raw_parts(req_ptr, std::mem::size_of::<ReportReq>())
        };

        let response_bytes: &mut [u8] = unsafe {
            let rsp_ptr = &mut report_response as *mut ReportRsp as *mut u8;
            std::slice::from_raw_parts_mut(rsp_ptr, std::mem::size_of::<ReportRsp>())
        };

        // Copy bytes from report_request to report_response
        response_bytes[..request_bytes.len()].copy_from_slice(request_bytes);

        let mut guest_report_request = GuestReportRequest::new(response_bytes.as_ref());

        CSV_GET_REPORT.ioctl(&mut self.0, &mut guest_report_request)?;

        report_response.signer.verify(&report_response.report.mnonce, &report_response.report.anonce)?;

        Ok((report_response.report, report_response.signer))
    }
}
