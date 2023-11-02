// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Interfaces for GuoMi that is not supported on rust-openssl.

use crate::crypto::key::ecc;
use libc::*;
use openssl_sys::*;
use std::{
    io::{Error, ErrorKind, Result},
    ptr,
};

#[cfg(ossl111)]
pub const EVP_PKEY_CTRL_SET1_ID: c_int = EVP_PKEY_ALG_CTRL + 11;

extern "C" {
    #[cfg(ossl111)]
    pub fn EVP_PKEY_set_alias_type(pkey: *mut EVP_PKEY, ttype: c_int) -> c_int;

    pub fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;

    #[cfg(ossl300)]
    pub fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int;
}

#[cfg(ossl111)]
#[allow(non_snake_case)]
pub unsafe fn EVP_PKEY_CTX_set1_id(
    ctx: *mut EVP_PKEY_CTX,
    id: *const c_void,
    id_len: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        -1,
        EVP_PKEY_CTRL_SET1_ID,
        id_len,
        id as *mut c_void,
    )
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SM2 {}

impl SM2 {
    /// use SM2 algorithm to verify a msg's signature

    pub fn verify(
        ecc_pubkey: ecc::PubKey,
        sig: &[u8],
        id: &Vec<u8>,
        msg: &Vec<u8>,
    ) -> Result<bool> {
        let mut verify_result = false;
        let pubkey_size = ecc_pubkey.g.size()?;

        unsafe {
            let eckey = EC_KEY_new_by_curve_name(NID_sm2);
            let pub_x = &ecc_pubkey.x[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let pub_y = &ecc_pubkey.y[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let bn_x = BN_bin2bn(
                pub_x.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            let bn_y = BN_bin2bn(
                pub_y.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y);
            let pkey = EVP_PKEY_new();
            if EVP_PKEY_assign(pkey, EVP_PKEY_SM2, eckey as *mut c_void) <= 0 {
                EVP_PKEY_free(pkey);
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "EVP_KEY_set1_EC_KEY failed",
                ));
            }

            #[cfg(ossl111)]
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

            let mctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            let pctx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
            EVP_PKEY_CTX_set1_id(pctx, id.as_ptr() as *mut c_void, id.len() as c_int);
            EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
            EVP_DigestVerifyInit(mctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), pkey);
            EVP_DigestVerifyUpdate(mctx, msg.as_ptr() as *mut c_void, msg.len());
            if EVP_DigestVerifyFinal(mctx, sig.as_ptr(), sig.len()) == 1 {
                verify_result = true;
            }
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(mctx);
        }

        Ok(verify_result)
    }
}
