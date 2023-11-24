// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    certs::csv::Certificate,
    error::{Error, Indeterminate},
    api::launch::{Policy, Session, Header, Measurement, AttestationReport},
    impl_const_id,
};

use std::{
    marker::PhantomData,
    mem::{size_of_val, MaybeUninit},
    os::{raw::c_ulong, unix::io::AsRawFd},
};

use iocuddle::*;

/// Initialize the CSV platform context.
#[repr(C)]
pub struct Init;

/// Initialize the CSV2 platform context.
#[repr(C)]
pub struct EsInit;

#[repr(transparent)]
pub struct Handle(u32);

impl From<LaunchStart<'_>> for Handle {
    fn from(ls: LaunchStart) -> Self {
        ls.handle
    }
}

/// Initiate CSV launch flow.
#[repr(C)]
pub struct LaunchStart<'a> {
    handle: Handle,
    policy: Policy,
    dh_addr: u64,
    dh_len: u32,
    session_addr: u64,
    session_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchStart<'a> {
    pub fn new(policy: &'a Policy, dh: &'a Certificate, session: &'a Session) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: dh as *const _ as _,
            dh_len: size_of_val(dh) as _,
            session_addr: session as *const _ as _,
            session_len: size_of_val(session) as _,
            _phantom: PhantomData,
        }
    }

    pub fn with_policy_only(policy: &'a Policy) -> Self {
        Self {
            handle: Handle(0), /* platform will generate one for us */
            policy: *policy,
            dh_addr: 0,
            dh_len: 0,
            session_addr: 0,
            session_len: 0,
            _phantom: PhantomData,
        }
    }
}

/// Encrypt guest data with its VEK.
#[repr(C)]
pub struct LaunchUpdateData<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchUpdateData<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Update VMSA for setting up vCPUs on CSV2.
#[repr(C)]
pub struct LaunchUpdateVmsa;

impl LaunchUpdateVmsa {
    pub fn new() -> Self {
        Self
    }
}

/// Inject a secret into the guest.
#[repr(C)]
pub struct LaunchSecret<'a> {
    hdr_addr: u64,
    hdr_len: u32,
    guest_addr: u64,
    guest_len: u32,
    trans_addr: u64,
    trans_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> LaunchSecret<'a> {
    pub fn new(header: &'a Header, guest: usize, trans: &'a [u8]) -> Self {
        Self {
            hdr_addr: header as *const _ as _,
            hdr_len: size_of_val(header) as _,
            guest_addr: guest as _,
            guest_len: trans.len() as _,
            trans_addr: trans.as_ptr() as _,
            trans_len: trans.len() as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the guest's measurement.
#[repr(C)]
pub struct LaunchMeasure<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a Measurement>,
}

impl<'a> LaunchMeasure<'a> {
    pub fn new(measurement: &'a mut MaybeUninit<Measurement>) -> Self {
        Self {
            addr: measurement.as_mut_ptr() as _,
            len: size_of_val(measurement) as _,
            _phantom: PhantomData,
        }
    }
}

/// Complete the CSV launch flow and transition guest into
/// ready state.
#[repr(C)]
pub struct LaunchFinish;

#[repr(C)]
pub struct Attestation<'a> {
    mnonce: [u8; 16],
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a AttestationReport>,
}

impl<'a> Attestation<'a> {
    pub fn new(ar: &'a mut MaybeUninit<AttestationReport>, mnonce: [u8; 16]) -> Self {
        Self {
            mnonce,
            addr: ar.as_mut_ptr() as _,
            len: size_of_val(ar) as _,
            _phantom: PhantomData,
        }
    }
}

// These enum ordinal values are defined in the Linux kernel
// source code: include/uapi/linux/kvm.h
impl_const_id! {
    /// The ioctl sub number
    pub Id => u32;

    Init = 0,
    EsInit = 1,
    LaunchStart<'_> = 2,
    LaunchUpdateData<'_> = 3,
    LaunchUpdateVmsa = 4,
    LaunchSecret<'_> = 5,
    LaunchMeasure<'_> = 6,
    LaunchFinish = 7,
    Attestation<'_> = 20,
}

const KVM: Group = Group::new(0xAE);
const ENC_OP: Ioctl<WriteRead, &c_ulong> = unsafe { KVM.write_read(0xBA) };

// Note: the iocuddle::Ioctl::lie() constructor has been used here because
// KVM_MEMORY_ENCRYPT_OP ioctl was defined like this:
//
// _IOWR(KVMIO, 0xba, unsigned long)
//
// Instead of something like this:
//
// _IOWR(KVMIO, 0xba, struct kvm_sev_cmd)
//
// which would require extra work to wrap around the design decision for
// that ioctl.

/// Initialize the CSV platform context.
pub const INIT: Ioctl<WriteRead, &Command<Init>> = unsafe { ENC_OP.lie() };

/// Initialize the CSV2 platform context.
pub const ES_INIT: Ioctl<WriteRead, &Command<EsInit>> = unsafe { ENC_OP.lie() };

/// Create encrypted guest context.
pub const LAUNCH_START: Ioctl<WriteRead, &Command<LaunchStart>> = unsafe { ENC_OP.lie() };

/// Encrypt guest data with its VEK.
pub const LAUNCH_UPDATE_DATA: Ioctl<WriteRead, &Command<LaunchUpdateData>> =
    unsafe { ENC_OP.lie() };

/// Encrypt the VMSA contents for CSV2.
pub const LAUNCH_UPDATE_VMSA: Ioctl<WriteRead, &Command<LaunchUpdateVmsa>> =
    unsafe { ENC_OP.lie() };

/// Inject a secret into the guest.
pub const LAUNCH_SECRET: Ioctl<WriteRead, &Command<LaunchSecret>> = unsafe { ENC_OP.lie() };

/// Get the guest's measurement.
pub const LAUNCH_MEASUREMENT: Ioctl<WriteRead, &Command<LaunchMeasure>> =
    unsafe { ENC_OP.lie() };

/// Complete the CSV launch flow and transition the guest into
/// the ready state.
pub const LAUNCH_FINISH: Ioctl<WriteRead, &Command<LaunchFinish>> = unsafe { ENC_OP.lie() };

pub const ATTESTATION: Ioctl<WriteRead, &Command<Attestation>> = unsafe { ENC_OP.lie() };

/// Corresponds to the `KVM_MEMORY_ENCRYPT_REG_REGION` ioctl
pub const ENC_REG_REGION: Ioctl<Write, &KvmEncRegion> =
    unsafe { KVM.read::<KvmEncRegion>(0xBB).lie() };

/// Corresponds to the kernel struct `kvm_enc_region`
#[repr(C)]
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
pub struct KvmEncRegion<'a> {
    addr: u64,
    size: u64,
    phantom: PhantomData<&'a [u8]>,
}

impl<'a> KvmEncRegion<'a> {
    /// Create a new `KvmEncRegion` referencing some memory assigned to the virtual machine.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            size: data.len() as _,
            phantom: PhantomData,
        }
    }

    /// Register the encrypted memory region to a virtual machine
    pub fn register(&mut self, vm_fd: &mut impl AsRawFd) -> std::io::Result<std::os::raw::c_uint> {
        ENC_REG_REGION.ioctl(vm_fd, self)
    }
}

/// A generic CSV command
#[repr(C)]
pub struct Command<'a, T: Id> {
    code: u32,
    data: u64,
    error: u32,
    csv_fd: u32,
    _phantom: PhantomData<&'a T>,
}

impl<'a, T: Id> Command<'a, T> {
    /// create the command from a mutable subcommand
    pub fn from_mut(csv: &'a mut impl AsRawFd, subcmd: &'a mut T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *mut T as _,
            error: 0,
            csv_fd: csv.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// create the command from a subcommand reference
    pub fn from(csv: &'a mut impl AsRawFd, subcmd: &'a T) -> Self {
        Self {
            code: T::ID,
            data: subcmd as *const T as _,
            error: 0,
            csv_fd: csv.as_raw_fd() as _,
            _phantom: PhantomData,
        }
    }

    /// encapsulate a `std::io::Error` in an `Indeterminate<Error>`
    pub fn encapsulate(&self, err: std::io::Error) -> Indeterminate<Error> {
        match self.error {
            0 => Indeterminate::<Error>::from(err),
            _ => Indeterminate::<Error>::from(self.error),
        }
    }
}
