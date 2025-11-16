//! This module experimental offer GPU security checks



use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::process::Command;

use ash::vk;
use ash::version::{EntryV1_0, InstanceV1_0};

use crate::{WinAuditError, WinError};

#[derive(Debug, Clone)]
pub(crate) struct AdapterInfo {
    pub name: String,
    pub vendor_id: u32,
    pub device_id: u32,
    pub api_version: vk::Version,
    pub driver_version: u32,
    pub supported_extensions: Vec<String>,
}

pub(crate) fn get_vulkan_adapters() -> Result<Vec<AdapterInfo>, WinAuditError> {
    let entry = match unsafe { ash::Entry::linked() } {
        Ok(e) => e,
        Err(_) => {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "Vulkan loader not found (ash::Entry::linked failed)",
                source: WinError::from_thread(),
            })
        }
    };

    let app_name = CString::new("winaudit-gpu-check").unwrap();
    let engine_name = CString::new("winaudit-engine").unwrap();
    let app_info = vk::ApplicationInfo::builder()
        .application_name(&app_name)
        .engine_name(&engine_name)
        .api_version(vk::make_api_version(0, 1, 0, 0));

    let create_info = vk::InstanceCreateInfo::builder().application_info(&app_info);

    let instance = unsafe {
        entry
            .create_instance(&create_info, None)
            .map_err(|e| WinAuditError::WinAuditError {
                failed_audit: "Failed to create Vulkan instance",
                source: WinError::from_thread(),
            })?
    };

    let phys_devices = unsafe {
        instance
            .enumerate_physical_devices()
            .map_err(|_| WinAuditError::WinAuditError {
                failed_audit: "Failed to enumerate Vulkan physical devices",
                source: WinError::from_thread(),
            })?
    };

    if phys_devices.is_empty() {
        unsafe { instance.destroy_instance(None); }
        return Err(WinAuditError::WinAuditError {
            failed_audit: "No Vulkan physical devices found",
            source: WinError::from_thread(),
        });
    }

    let mut adapters = Vec::with_capacity(phys_devices.len());

    for pd in phys_devices {
        let props = unsafe { instance.get_physical_device_properties(pd) };
        let raw_name = unsafe { CStr::from_ptr(props.device_name.as_ptr() as *const c_char) };
        let name = raw_name.to_string_lossy().to_string();

        let vendor_id = props.vendor_id;
        let device_id = props.device_id;
        let driver_version = props.driver_version;
        let api_version = props.api_version;

        let exts = unsafe {
            instance
                .enumerate_device_extension_properties(pd)
                .map_err(|_| WinAuditError::WinAuditError {
                    failed_audit: "Failed to enumerate device extension properties",
                    source: WinError::from_thread(),
                })?
        };
        let mut supported_extensions = Vec::with_capacity(exts.len());
        for e in exts {
            let n = unsafe { CStr::from_ptr(e.extension_name.as_ptr() as *const c_char) }
                .to_string_lossy()
                .to_string();
            supported_extensions.push(n);
        }

        adapters.push(AdapterInfo {
            name,
            vendor_id,
            device_id,
            api_version: vk::Version::from_raw(api_version),
            driver_version,
            supported_extensions,
        });
    }

    unsafe { instance.destroy_instance(None); }

    Ok(adapters)
}

pub(crate) fn is_gpu_from_trusted_vendor(adapter: &AdapterInfo) -> bool {
    match adapter.vendor_id {
        0x10DE  | 0x1002 | 0x8086 => true,
        _ => false,
    }
}

/// Check if all requested device extensions are supported by the adapter
pub(crate) fn is_gpu_supports_extensions(adapter: &AdapterInfo, extensions: &[&str]) -> bool {
    extensions.iter().all(|req| {
        adapter
            .supported_extensions
            .iter()
            .any(|have| have.eq_ignore_ascii_case(req))
    })
}

/// Check whether the system has any Vulkan device (=> SPIR-V pipeline usable)
pub(crate) fn is_gpu_supports_spirv() -> Result<bool, WinAuditError> {
    match get_vulkan_adapters() {
        Ok(adapters) => Ok(!adapters.is_empty()),
        Err(e) => Err(e),
    }
}

/// Check whether GPU advertises support for protected memory extension.
pub(crate) fn is_gpu_supports_protected_memory() -> Result<bool, WinAuditError> {
    let adapters = get_vulkan_adapters()?;
    let candidates = &[
        "VK_EXT_protected_memory",
        "VK_KHR_external_memory",
        "VK_KHR_external_memory_win32",
        "VK_EXT_external_memory_host",
    ];

    for a in adapters {
        if is_gpu_supports_extensions(&a, candidates) {
            return Ok(true);
        }
    }
    Ok(false)
}
