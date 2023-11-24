// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Modules for interfacing with CSV Firmware
//! Rust-fridenly API wrappers to communicate the the FFI functions.

pub(crate) mod ioctl;
use ioctl::*;

use crate::*;
use crate::util::*;

use serde::{Deserialize, Serialize};
use bitflags::bitflags;
use std::{
    os::unix::io::AsRawFd,
    convert::*,
    io::{Read, Result, Write},
    mem::MaybeUninit,
};

/// Launcher type-state that indicates a brand new launch.
pub struct New;

/// Launcher type-state that indicates an in-progress launch.
pub struct Started(Handle);

/// Launcher type-state that indicates the availability of a measurement.
pub struct Measured(Handle, Measurement);

/// Facilitates the correct execution of the CSV launch process.
pub struct Launcher<T, U: AsRawFd, V: AsRawFd> {
    state: T,
    vm_fd: U,
    csv: V,
}

impl<T, U: AsRawFd, V: AsRawFd> Launcher<T, U, V> {
    /// Give access to the vm fd to create vCPUs or such.
    pub fn as_mut_vmfd(&mut self) -> &mut U {
        &mut self.vm_fd
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<New, U, V> {
    /// Begin the CSV launch process.
    pub fn new(kvm: U, csv: V) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd: kvm,
            csv,
            state: New,
        };

        let mut cmd = Command::from(&mut launcher.csv, &Init);
        INIT.ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Begin the CSV2 launch process.
    pub fn new_es(kvm: U, csv: V) -> Result<Self> {
        let mut launcher = Launcher {
            vm_fd: kvm,
            csv,
            state: New,
        };

        let mut cmd = Command::from(&mut launcher.csv, &EsInit);
        ES_INIT
            .ioctl(&mut launcher.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(launcher)
    }

    /// Create an encrypted guest context.
    pub fn start(mut self, start: Start) -> Result<Launcher<Started, U, V>> {
        let mut launch_start = LaunchStart::new(&start.policy, &start.cert, &start.session);
        let mut cmd = Command::from_mut(&mut self.csv, &mut launch_start);
        LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Started(launch_start.into()),
            vm_fd: self.vm_fd,
            csv: self.csv,
        };

        Ok(next)
    }

    /// Create an encrypted guest context.
    pub fn start_raw(
        mut self,
        policy: &Policy,
        cert: &crate::certs::csv::Certificate,
        session: &Session,
    ) -> Result<Launcher<Started, U, V>> {
        let mut launch_start = LaunchStart::new(policy, cert, session);
        let mut cmd = Command::from_mut(&mut self.csv, &mut launch_start);
        LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Started(launch_start.into()),
            vm_fd: self.vm_fd,
            csv: self.csv,
        };

        Ok(next)
    }

    /// Create an encrypted guest context.
    pub fn start_with_policy_only(mut self, policy: Policy) -> Result<Launcher<Started, U, V>> {
        let mut launch_start = LaunchStart::with_policy_only(&policy);
        let mut cmd = Command::from_mut(&mut self.csv, &mut launch_start);
        LAUNCH_START
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Started(launch_start.into()),
            vm_fd: self.vm_fd,
            csv: self.csv,
        };

        Ok(next)
    }

}

impl<U: AsRawFd, V: AsRawFd> Launcher<Started, U, V> {
    /// Encrypt guest data with its VEK.
    pub fn update_data(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        let mut cmd = Command::from(&mut self.csv, &launch_update_data);

        KvmEncRegion::new(data).register(&mut self.vm_fd)?;

        LAUNCH_UPDATE_DATA
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Register the encrypted memory region to a virtual machine.
    /// Corresponds to the `KVM_MEMORY_ENCRYPT_REG_REGION` ioctl.
    pub fn register_kvm_enc_region(&mut self, data: &[u8]) -> Result<()> {
        KvmEncRegion::new(data).register(&mut self.vm_fd)?;
        Ok(())
    }

    /// Encrypt guest data with its VEK, while the KVM encrypted memory region is not registered.
    pub fn update_data_without_registration(&mut self, data: &[u8]) -> Result<()> {
        let launch_update_data = LaunchUpdateData::new(data);
        let mut cmd = Command::from(&mut self.csv, &launch_update_data);

        LAUNCH_UPDATE_DATA
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Encrypt the VMSA on CSV2.
    pub fn update_vmsa(&mut self) -> Result<()> {
        let launch_update_vmsa = LaunchUpdateVmsa::new();
        let mut cmd = Command::from(&mut self.csv, &launch_update_vmsa);

        LAUNCH_UPDATE_VMSA
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(())
    }

    /// Request a measurement from the CSV firmware.
    pub fn measure(mut self) -> Result<Launcher<Measured, U, V>> {
        let mut measurement = MaybeUninit::uninit();
        let mut launch_measure = LaunchMeasure::new(&mut measurement);
        let mut cmd = Command::from_mut(&mut self.csv, &mut launch_measure);
        LAUNCH_MEASUREMENT
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        let next = Launcher {
            state: Measured(self.state.0, unsafe { measurement.assume_init() }),
            vm_fd: self.vm_fd,
            csv: self.csv,
        };

        Ok(next)
    }
}

impl<U: AsRawFd, V: AsRawFd> Launcher<Measured, U, V> {
    /// Get the measurement that the CSV platform recorded.
    pub fn measurement(&self) -> Measurement {
        self.state.1
    }

    /// Get the attestation report.
    pub fn get_attestation_report(&mut self, mnonce: [u8; 16]) -> Result<Box<AttestationReport>> {
        let mut ar = MaybeUninit::uninit();
        let mut attestation = Attestation::new(&mut ar, mnonce);
        let mut cmd = Command::from_mut(&mut self.csv, &mut attestation);
        ATTESTATION
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;

        Ok(Box::new(unsafe { ar.assume_init() }))
    }

    /// Inject a secret into the guest.
    ///
    /// ## Remarks
    ///
    /// This should only be called after a successful attestation flow.
    pub fn inject(&mut self, secret: &Secret, guest: usize) -> Result<()> {
        let launch_secret = LaunchSecret::new(&secret.header, guest, &secret.ciphertext[..]);
        let mut cmd = Command::from(&mut self.csv, &launch_secret);
        LAUNCH_SECRET
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(())
    }

    /// Complete the CSV launch process.
    pub fn finish(mut self) -> Result<Handle> {
        let mut cmd = Command::from(&mut self.csv, &LaunchFinish);
        LAUNCH_FINISH
            .ioctl(&mut self.vm_fd, &mut cmd)
            .map_err(|e| cmd.encapsulate(e))?;
        Ok(self.state.0)
    }
}

bitflags! {
    /// Configurable CSV Policy options.
    #[derive(Default, Deserialize, Serialize)]
    pub struct PolicyFlags: u16 {
        /// When set, debugging the guest is forbidden.
        const NO_DEBUG        = 0b00000001u16.to_le();

        /// When set, sharing keys with other guests is prohibited.
        const NO_KEY_SHARING  = 0b00000010u16.to_le();

        /// When set, CSV2 protections are required.
        const ENCRYPTED_STATE = 0b00000100u16.to_le();

        /// When set, the guest may not be sent to another platform.
        const NO_SEND         = 0b00001000u16.to_le();

        /// When set, the guest may not be transmitted to a platform
        /// that is outside of the domain.
        const DOMAIN          = 0b00010000u16.to_le();

        /// When set, the guest may not be transmitted to another
        /// platform that is not CSV-capable.
        const CSV             = 0b00100000u16.to_le();
    }
}

/// Describes a policy that the HYGON Secure Processor will
/// enforce.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Policy {
    /// The various policy optons are encoded as bit flags.
    pub flags: PolicyFlags,

    /// The desired minimum platform firmware version.
    pub minfw: Version,
}

/// Convert a policy represented as a u32 to a Policy struct.
impl From<u32> for Policy {
    fn from(p: u32) -> Self {
        let flags = p as u16;
        let flags = PolicyFlags::from_bits_truncate(flags);

        let p = p >> 16;
        let p = p as u16;
        let minfw = Version::from(p);

        Self { flags, minfw }
    }
}

/// A secure channel between the tenant and the HYGON Secure
/// Processor.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// Used for deriving a shared secret between the tenant
    /// and the HYGON SP.
    pub nonce: [u8; 16],

    /// The TEK and TIK concatenated together and wrapped by
    /// the Key Encryption Key and the Key Integrity Key.
    /// (KIK (KEK (TEK|TIK))).
    pub wrap_tk: [u8; 32],

    /// The initialization vector.
    pub wrap_iv: [u8; 16],

    /// Integrity protection for the wrapped keys (see the
    /// `wrap_tk` field of this struct).
    pub wrap_mac: [u8; 32],

    /// The integrity-protected CSV policy.
    pub policy_mac: [u8; 32],
}

/// Used to establish a secure session with the HYGON SP.
#[repr(C)]
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct Start {
    /// The tenant's policy for this CSV guest.
    pub policy: Policy,

    /// The tenant's Diffie-Hellman certificate.
    pub cert: certs::csv::Certificate,

    /// A secure channel with the HYGON SP.
    pub session: Session,
}

impl codicon::Decoder<()> for Start {
    type Error = std::io::Error;

    fn decode(mut reader: impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl codicon::Encoder<()> for Start {
    type Error = std::io::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

bitflags! {
    /// Additional descriptions of the secret header packet.
    #[derive(Default, Deserialize, Serialize)]
    pub struct HeaderFlags: u32 {
        /// If set, the contents of the packet are compressed and
        /// the HYGON SP must decompress them.
        const COMPRESSED = 0b00000001u32.to_le();
    }
}

/// The header for a data packet that contains secret information
/// to be injected into the guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Header {
    /// Describes the secret packet (for example: if it is
    /// compressed).
    pub flags: HeaderFlags,

    /// The initialization vector.
    pub iv: [u8; 16],

    /// Integrity protection MAC.
    pub mac: [u8; 32],
}

/// A packet containing secret information to be injected
/// into the guest.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Secret {
    /// The header for this packet.
    pub header: Header,

    /// The encrypted secret to inject.
    pub ciphertext: Vec<u8>,
}

/// A measurement of the CSV guest.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Measurement {
    /// The measurement.
    pub measure: [u8; 32],

    /// A random nonce.
    pub mnonce: [u8; 16],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AttestationReport {
    ///
    pub mnonce: [u8; 16],
    ///
    pub digest: [u8; 32],
    ///
    pub policy: Policy,
    ///
    pub sig_usage: [u8; 4],
    ///
    pub sig_algo: [u8; 4],
    ///
    reserved: [u8; 4],
    ///
    pub sig1: [[u8; 16]; 9],
}
