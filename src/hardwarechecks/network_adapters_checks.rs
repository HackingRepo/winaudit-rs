use crate::WinAuditError;
use crate::hardwarechecks::windows_defs::*;

use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;
use windows::core::PCWSTR;

use std::ptr;

#[allow(dead_code)]
pub(crate) fn is_sriov_enabled(adapter_device_path: &str) -> Result<bool, WinAuditError> {
    unsafe {
        let wide: Vec<u16> = adapter_device_path.encode_utf16().chain(Some(0)).collect();

        let handle = CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(ptr::null()),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            Some(HANDLE::default()),
        );

        if handle == Ok(INVALID_HANDLE_VALUE) {
            return Err(WinAuditError::from(
                "Failed to open network adapter device path",
            ));
        }

        let mut sriov_capable: u32 = 0;
        let mut bytes = 0u32;

        let handle = HANDLE::default();

        let result = DeviceIoControl(
            handle,
            IOCTL_NDIS_QUERY_GLOBAL_STATS,
            Some(&OID_GEN_SRIOV_CAPABLE as *const _ as *mut _),
            std::mem::size_of::<u32>() as u32,
            Some(&mut sriov_capable as *mut _ as *mut _),
            std::mem::size_of::<u32>() as u32,
            Some(&mut bytes),
            Some(ptr::null_mut()),
        );

        CloseHandle(handle)?;

        match result {
            Ok(_) => return Ok(sriov_capable != 0),
            Err(_) => {
                return Err(WinAuditError::from(
                    "DeviceIoControl failed for SRIOV capability",
                ));
            }
        }
    }
}
