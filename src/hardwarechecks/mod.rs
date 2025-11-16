//! This module provides security hardware checks for Windows systems
#![allow(unused_imports)]

use crate::{WinAuditError, hresult_to_audit_error, win32_to_audit_error};
use std::path::Path;
use windows::Win32::Foundation::*;
use windows::Win32::System::SystemInformation::{FIRMWARE_TYPE, FirmwareTypeUefi, GetFirmwareType};
use windows::Win32::System::Threading::{IsProcessorFeaturePresent, PROCESSOR_FEATURE_ID};
use windows::Win32::System::WindowsProgramming::GetFirmwareEnvironmentVariableW;
use windows_core::PCWSTR;
use winreg::RegKey;
use winreg::enums::*;
pub mod windows_defs;

/// Check if TPM is present
pub fn is_tpm() -> Result<bool, WinAuditError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SOFTWARE\Microsoft\Cryptography") {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if Secure Boot is enabled
pub fn is_secure_boot_enabled() -> Result<bool, WinAuditError> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    match hklm.open_subkey(r"SYSTEM\CurrentControlSet\Control\SecureBoot\State") {
        Ok(key) => {
            let val = key
                .get_value::<u32, _>("UEFISecureBootEnabled")
                .unwrap_or(0);
            Ok(val == 1)
        }
        Err(_) => Ok(false),
    }
}

const PF_NX_ENABLED: u32 = 12;
const PF_SECOND_LEVEL_ADDRESS_TRANSLATION: u32 = 20;
const PF_VIRT_FIRMWARE_ENABLED: u32 = 21;
const PF_SPECULATION_CONTROL_PRESENT: u32 = 45;
const PF_SSE3_INSTRUCTIONS_AVAILABLE: u32 = 49;
const PF_SUPERVISOR_EXECUTION_PREVENTION: u32 = 50;
const PF_SUPERVISOR_ACCESS_PREVENTION: u32 = 51;
const PF_MACHINE_CHECK_ENABLE: u32 = 52;
#[cfg(target_arch = "x86_64")]
const PF_RDRAND_INSTRUCTION_AVAILABLE: u32 = 53;

#[cfg(target_arch = "x86_64")]
const PF_AVX_INSTRUCTIONS_AVAILABLE: u32 = 54;
#[cfg(target_arch = "x86_64")]
const PF_AVX2_INSTRUCTIONS_AVAILABLE: u32 = 55;

#[cfg(target_arch = "arm")]
const PF_NEON_INSTRUCTIONS_AVAILABLE: u32 = 54;
#[cfg(target_arch = "arm")]
const PF_NEON_FMA_INSTRUCTIONS_AVAILABLE: u32 = 55;
#[cfg(target_arch = "arm")]
const PF_NEON_NEON_INSTRUCTIONS_AVAILABLE: u32 = 56;
#[cfg(target_arch = "arm")]
const PF_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 57;

pub fn cpu_support_nx() -> Result<bool, WinAuditError> {
    unsafe { Ok(IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_NX_ENABLED)).as_bool()) }
}

pub fn cpu_support_second_level_address_translation() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_SECOND_LEVEL_ADDRESS_TRANSLATION))
                .as_bool(),
        )
    }
}

pub fn cpu_support_virt_firmware() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_VIRT_FIRMWARE_ENABLED)).as_bool())
    }
}

pub fn cpu_support_speculation_control() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_SPECULATION_CONTROL_PRESENT))
                .as_bool(),
        )
    }
}

pub fn cpu_support_sse3() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_SSE3_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}

pub fn cpu_support_supervisor_execution_prevention() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_SUPERVISOR_EXECUTION_PREVENTION))
                .as_bool(),
        )
    }
}

pub fn cpu_support_supervisor_access_prevention() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_SUPERVISOR_ACCESS_PREVENTION))
                .as_bool(),
        )
    }
}

pub fn cpu_support_machine_check() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_MACHINE_CHECK_ENABLE)).as_bool())
    }
}

#[cfg(target_arch = "x86_64")]
pub fn cpu_support_rdrand() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_RDRAND_INSTRUCTION_AVAILABLE))
                .as_bool(),
        )
    }
}
#[cfg(target_arch = "x86_64")]
pub fn cpu_support_avx() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_AVX_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}

#[cfg(target_arch = "x86_64")]
pub fn cpu_support_avx2() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_AVX2_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}

#[cfg(target_arch = "arm")]
pub fn cpu_support_neon() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_NEON_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}
#[cfg(target_arch = "arm")]
pub fn cpu_support_neon_fma() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_NEON_FMA_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}
#[cfg(target_arch = "arm")]
pub fn cpu_support_neon_neon() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_NEON_NEON_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}

#[cfg(target_arch = "arm")]
pub fn cpu_support_crypto() -> Result<bool, WinAuditError> {
    unsafe {
        Ok(
            IsProcessorFeaturePresent(PROCESSOR_FEATURE_ID(PF_CRYPTO_INSTRUCTIONS_AVAILABLE))
                .as_bool(),
        )
    }
}

/// Check if BIOS is UEFI
pub fn is_bios_uefi() -> Result<bool, WinAuditError> {
    unsafe {
        let mut t = FIRMWARE_TYPE(0);

        GetFirmwareType(&mut t).map_err(|e| WinAuditError::from(e))?;

        Ok(t.0 == FirmwareTypeUefi.0)
    }
}

/// Check if Memory Guard / HVCI is enabled
pub fn is_memory_guard_enabled() -> Result<bool, WinAuditError> {
    let keys = [
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity",
        "SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\KernelDMAProtection",
    ];
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    for key in keys.iter() {
        if let Ok(k) = hklm.open_subkey(key) {
            if let Ok(val) = k.get_value::<u32, _>("Enabled") {
                if val == 1 {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

/// Check if UEFI Secure Variables Protection is enabled
pub fn is_uefi_secure_variables_protection() -> Result<bool, WinAuditError> {
    let var_name = widestring::U16CString::from_str("SecureBoot").unwrap();
    let guid = widestring::U16CString::from_str("{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}").unwrap();

    let mut buffer = [0u8; 1];
    unsafe {
        let result = GetFirmwareEnvironmentVariableW(
            PCWSTR(var_name.as_ptr()),
            PCWSTR(guid.as_ptr()),
            Some(buffer.as_mut_ptr() as *mut _),
            buffer.len() as u32,
        );
        Ok(result != 0)
    }
}

#[cfg(feature = "experimental")]
mod network_adapters_checks;
#[cfg(feature = "experimental")]
pub use network_adapters_checks::*;
#[cfg(feature = "experimental")]
mod ssd_checks;
#[cfg(feature = "experimental")]
pub use ssd_checks::*;
