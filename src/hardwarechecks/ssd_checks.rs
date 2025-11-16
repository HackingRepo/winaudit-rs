use crate::hardwarechecks::windows_defs::*;
use crate::{WinAuditError, hresult_to_audit_error};

use windows::Win32::Foundation::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::IO::*;
use windows::core::PCWSTR;

use std::ptr;
use widestring::U16CString;

#[allow(dead_code)]
pub(crate) fn is_ssd_self_encrypted(drive_path: &str) -> Result<bool, WinAuditError> {
    unsafe {
        let drive_wide = U16CString::from_str(drive_path)
            .map_err(|_| WinAuditError::from("Invalid drive path"))?
            .into_vec_with_nul();

        let handle = CreateFileW(
            PCWSTR(drive_wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            Some(ptr::null()),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            Some(HANDLE::default()),
        )
        .map_err(|e| {
            let inner = hresult_to_audit_error(e.into(), "CreateFileW failed for SSD IOCTL check");

            match inner {
                Ok(_) => WinAuditError::CustomError {
                    failed_audit: "Unknown",
                    message: "Unexpected success in error path",
                },
                Err(err) => err,
            }
        })?;

        let mut query: STORAGE_PROPERTY_QUERY = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceSecurityProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };

        let mut out_buffer = [0u8; 1024];
        let mut bytes = 0u32;

        let result = DeviceIoControl(
            handle,
            IOCTL_STORAGE_QUERY_PROPERTY,
            Some(&mut query as *mut _ as *mut _),
            std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            Some(out_buffer.as_mut_ptr() as *mut _),
            out_buffer.len() as u32,
            Some(&mut bytes),
            Some(ptr::null_mut()),
        );

        CloseHandle(handle)?;

        match result {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }
}
