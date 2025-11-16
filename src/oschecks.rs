//! This module provide OS Security checks for Windows systems

#![allow(non_camel_case_types)]
#![allow(unused_imports)]

use crate::{WinAuditError, hresult_to_audit_error, win32_to_audit_error};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::os::raw::c_void;
use std::os::windows::ffi::OsStrExt as _;

use std::process::Command;
use windows::Win32::Devices::Bluetooth::{
    BLUETOOTH_FIND_RADIO_PARAMS, BLUETOOTH_RADIO_INFO, BluetoothFindFirstRadio,
    BluetoothFindRadioClose, BluetoothGetRadioInfo,
};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::NetManagement::*;
use windows::Win32::NetworkManagement::WiFi::*;
use windows::Win32::Storage::FileSystem::*;
use windows::Win32::System::Com::{
    CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
    CoUninitialize,
};
use windows::Win32::System::Registry::{
    REG_ROUTINE_FLAGS, REG_SAM_FLAGS, REG_VALUE_TYPE, RRF_RT_REG_BINARY, RRF_RT_REG_DWORD,
    RRF_RT_REG_SZ, RegCloseKey, RegEnumValueW, RegGetValueW, RegOpenKeyExA, RegOpenKeyExW,
    RegQueryValueExA,
};
use windows::Win32::System::SystemInformation::*;
use windows::Win32::System::SystemServices::PROCESS_MITIGATION_ASLR_POLICY;
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetProcessDEPPolicy, GetProcessMitigationPolicy,
    PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION, PROCESS_DEP_ENABLE, ProcessASLRPolicy,
};
use windows::Win32::System::UpdateAgent::{IUpdateSearcher, IUpdateSession};
use windows::core::{
    BSTR, Error as WinError, Interface, PCSTR, PCWSTR, PWSTR, Result as WinResult,
};
use windows_core::{BOOL, GUID, HRESULT};
use winreg::RegKey;
use winreg::enums::*;

// Import RtlGetVersion from ntdll.dll
#[link(name = "ntdll")]
unsafe extern "system" {
    unsafe fn RtlGetVersion(lpVersionInformation: *mut OSVERSIONINFOEXW) -> i32;
}

// Import DeviceIoControl from kernel32.dll
#[link(name = "kernel32")]
unsafe extern "system" {
    pub(crate) unsafe fn DeviceIoControl(
        hDevice: HANDLE,
        dwIoControlCode: u32,
        lpInBuffer: *const std::ffi::c_void,
        nInBufferSize: u32,
        lpOutBuffer: *mut std::ffi::c_void,
        nOutBufferSize: u32,
        lpBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
    ) -> i32;
}

pub struct WinVer {
    pub win_ver: f32,
    pub build_number: u16,
}

/// All Windows versions that reached End-of-Life (without build numbers)
pub const WINVERSION_END_OF_LIFE: &[f32] = &[
    3.1,    // Windows 3.1
    95.0,   // Windows 95
    98.0,   // Windows 98
    98.1,   // Windows 98 SE
    2000.0, // Windows 2000
    4.9,    // Windows ME
    5.1,    // Windows XP
    6.0,    // Windows Vista
    7.0,    // Windows 7
    8.0,    // Windows 8
    8.1,    // Windows 8.1
    10.0,   // Windows 10 (some builds)
];

/// Windows 11 build numbers
pub const WINBUILD_11_END_OF_LIFE: &[u16] = &[
    21, // 21H2
    22, // 22H2
    23, // 23H2
];

macro_rules! audit_try {
    ($audit:expr, $expr:expr) => {
        $expr.map_err(|e| WinAuditError::WinAuditError {
            failed_audit: $audit,
            source: e,
        })
    };
}

/// Get the current Windows version and build number
pub fn get_current_windows_version() -> Result<WinVer, WinAuditError> {
    unsafe {
        let mut os_info: OSVERSIONINFOEXW = std::mem::zeroed();
        os_info.dwOSVersionInfoSize = std::mem::size_of::<OSVERSIONINFOEXW>() as u32;

        let status = RtlGetVersion(&mut os_info as *mut _);

        if status == 0 {
            Ok(WinVer {
                win_ver: os_info.dwMajorVersion as f32 + os_info.dwMinorVersion as f32 / 10.0,
                build_number: os_info.dwBuildNumber as u16,
            })
        } else {
            Err(WinAuditError::WinAuditError {
                failed_audit: "Failed to get Windows version",
                source: WinError::from_hresult(windows_core::HRESULT(status)),
            })
        }
    }
}

/// Check is the Windows Version currently running is EOL, This important for Security
pub fn is_win_version_eol() -> Result<bool, WinAuditError> {
    let current = get_current_windows_version()?;

    if WINVERSION_END_OF_LIFE.contains(&current.win_ver) {
        Ok(true)
    } else {
        // Check the Build of Windows 11 is not EOL
        Ok(WINBUILD_11_END_OF_LIFE.contains(&current.build_number))
    }
}

/// This check is the windows version safe and supported not EOL
/// This counterpart of `is_win_version_eol`
pub fn is_win_version_safe() -> Result<bool, WinAuditError> {
    Ok(!is_win_version_eol()?)
}

/// This check is ASLR enabled for the current process
pub fn is_aslr_enabled_for_current_process() -> Result<bool, WinAuditError> {
    unsafe {
        let mut policy = PROCESS_MITIGATION_ASLR_POLICY::default();

        let result: Result<(), windows_core::Error> = GetProcessMitigationPolicy(
            GetCurrentProcess(),
            ProcessASLRPolicy,
            &mut policy as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_MITIGATION_ASLR_POLICY>(),
        );

        match result {
            Ok(()) => {
                let flags = policy.Anonymous.Flags;
                let enable_bottom_up_randomization = (flags & 0x1) != 0;
                let enable_force_relocate_images = (flags & 0x2) != 0;
                let enable_high_entropy = (flags & 0x4) != 0;

                Ok(enable_bottom_up_randomization
                    || enable_force_relocate_images
                    || enable_high_entropy)
            }
            Err(err) => Err(WinAuditError::WinAuditError {
                failed_audit: "Failed to query ASLR policy for current process",
                source: err,
            }),
        }
    }
}

/// Check is the ASLR enabled at system level
pub fn is_aslr_enabled_for_system() -> Result<bool, WinAuditError> {
    unsafe {
        let mut value: u32 = 0;
        let mut size = std::mem::size_of::<u32>() as u32;

        let subkey: Vec<u16> =
            OsStr::new("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

        let valuename: Vec<u16> = OsStr::new("MoveImages")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let win_result = RegGetValueW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(subkey.as_ptr()),
            PCWSTR(valuename.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut value as *mut _ as *mut c_void),
            Some(&mut size),
        );

        if win_result != WIN32_ERROR(0) {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "Failed to read MoveImages registry value",
                source: WinError::from(win_result),
            });
        }

        if value != 0 {
            return Ok(true);
        }

        let kernel_subkey: Vec<u16> =
            OsStr::new("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel")
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

        let kernel_value: Vec<u16> = OsStr::new("MitigationOptions")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut mitigation_data = [0u8; 8];
        let mut mitigation_size = mitigation_data.len() as u32;

        let kernel_win_result = RegGetValueW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(kernel_subkey.as_ptr()),
            PCWSTR(kernel_value.as_ptr()),
            RRF_RT_REG_BINARY,
            None,
            Some(mitigation_data.as_mut_ptr() as *mut _),
            Some(&mut mitigation_size),
        );

        if kernel_win_result != WIN32_ERROR(0) {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "Failed to read MitigationOptions registry value",
                source: WinError::from(kernel_win_result),
            });
        }

        let mitigation_flags = u64::from_le_bytes(mitigation_data);
        Ok((mitigation_flags & 0x3) != 0)
    }
}

/// This check is only Administrator users exist in the system
/// If only Administrator this is a security risk
/// Users encourged to create an normal user
pub fn is_only_administrator_user_exist() -> Result<bool, WinAuditError> {
    unsafe {
        let mut buffer: *mut USER_INFO_0 = std::ptr::null_mut();
        let mut entries_read: u32 = 0;
        let mut total_entries: u32 = 0;

        let status = NetUserEnum(
            PCWSTR::null(),
            0,
            FILTER_NORMAL_ACCOUNT,
            &mut buffer as *mut _ as *mut _,
            MAX_PREFERRED_LENGTH,
            &mut entries_read,
            &mut total_entries,
            None,
        );

        if status != NERR_Success {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "NetUserEnum failed",
                source: WinError::from(WIN32_ERROR(status as u32)),
            });
        }

        let users = std::slice::from_raw_parts(buffer, entries_read as usize);
        let mut user_count = 0;
        let mut has_non_admin = false;

        for user in users {
            if !user.usri0_name.is_null() {
                let wide = windows::core::PCWSTR(user.usri0_name.0);
                let len = (0..).take_while(|&i| *wide.0.add(i) != 0).count();
                let username = String::from_utf16_lossy(std::slice::from_raw_parts(wide.0, len));

                user_count += 1;

                if username.to_lowercase() != "administrator" {
                    has_non_admin = true;
                    break;
                }
            }
        }

        NetApiBufferFree(Some(buffer as *mut _));

        Ok(user_count == 1 && !has_non_admin)
    }
}

/// This check is Windows Security Questions disabled
/// This important to security!
/// Security Questions are unsafe for reset password, Because theses answers may already exist on Social Media or The Internet
pub fn is_security_questions_disabled() -> Result<bool, WinAuditError> {
    unsafe {
        const CHECKS: &[(&str, &str)] = &[
            (
                "SOFTWARE\\Policies\\Microsoft\\Windows\\System",
                "TurnOffSecurityQuestions",
            ),
            (
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "SecurityQuestionsDisabled",
            ),
            (
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                "NoLocalPasswordReset",
            ),
            (
                "SOFTWARE\\Policies\\Microsoft\\Windows\\System\\PasswordReset",
                "Disable",
            ),
        ];

        let mut hkey: windows::Win32::System::Registry::HKEY =
            windows::Win32::System::Registry::HKEY::default();

        for (subkey, value_name) in CHECKS {
            let path: Vec<u16> = subkey.encode_utf16().chain(Some(0)).collect();

            if RegOpenKeyExW(
                windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
                PCWSTR(path.as_ptr()),
                Some(0),
                REG_SAM_FLAGS(KEY_READ),
                &mut hkey,
            ) != WIN32_ERROR(0)
            {
                continue;
            }

            let name: Vec<u16> = value_name.encode_utf16().chain(Some(0)).collect();
            let mut data: u32 = 0;
            let mut size = std::mem::size_of::<u32>() as u32;

            let reg_res = RegGetValueW(
                hkey,
                PCWSTR(std::ptr::null()),
                PCWSTR(name.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut data as *mut _ as *mut _),
                Some(&mut size),
            );

            if reg_res == WIN32_ERROR(0) {
                if data == 1 {
                    return Ok(true);
                }
            } else {
                let mut buffer: [u16; 512] = [0; 512];
                let mut buf_size = buffer.len() as u32 * 2;

                let string_res = RegGetValueW(
                    hkey,
                    PCWSTR(std::ptr::null()),
                    PCWSTR(name.as_ptr()),
                    RRF_RT_REG_SZ,
                    None,
                    Some(buffer.as_mut_ptr() as *mut _),
                    Some(&mut buf_size),
                );

                if string_res == WIN32_ERROR(0) {
                    let s = String::from_utf16_lossy(&buffer[..(buf_size / 2) as usize]);
                    let sval = s.trim().to_lowercase();
                    if sval == "1" || sval == "true" || sval == "yes" {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }
}

/// Check is bitlocker enabled or not
pub fn is_bitlocker_enabled() -> Result<bool, WinAuditError> {
    use windows::Win32::System::Registry::HKEY;
    unsafe {
        const BITLOCKER_REG_KEY: &str = r"SOFTWARE\Policies\Microsoft\FVE";
        const BITLOCKER_ENABLED_VALUES: &[&str] = &[
            "RDVPassphraseEnabled",
            "UseBitLockerToGo",
            "EnableBDEWithNoTPM",
            "FDVRequireActiveDirectoryBackup",
        ];

        let hklm = HKEY_LOCAL_MACHINE;

        let mut key = windows::Win32::System::Registry::HKEY::default();
        let path: Vec<u16> = BITLOCKER_REG_KEY.encode_utf16().chain(Some(0)).collect();

        if RegOpenKeyExW(
            HKEY(hklm),
            PCWSTR(path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut key,
        ) == WIN32_ERROR(0)
        {
            for name in BITLOCKER_ENABLED_VALUES {
                let name_w: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
                let mut data: u32 = 0;
                let mut size = std::mem::size_of::<u32>() as u32;

                let res = RegGetValueW(
                    key,
                    PCWSTR(std::ptr::null()),
                    PCWSTR(name_w.as_ptr()),
                    RRF_RT_REG_DWORD,
                    None,
                    Some(&mut data as *mut _ as *mut _),
                    Some(&mut size),
                );

                if res == WIN32_ERROR(0) && data == 1 {
                    return Ok(true);
                }
            }
        }

        let output: Result<std::process::Output, std::io::Error> = std::process::Command::new("sc")
            .args(&["query", "BDESVC"])
            .output();

        if let Ok(output) = output {
            if String::from_utf8_lossy(&output.stdout).contains("RUNNING") {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Check is a specific drive locked by BitLocker
pub fn is_drive_locked_with_bitlocker(drive_letter: &str) -> Result<bool, WinAuditError> {
    if !is_bitlocker_enabled()? {
        return Ok(false);
    }

    let mut path = drive_letter.trim().to_string();
    if !path.ends_with('\\') {
        path.push('\\');
    }

    let wide: Vec<u16> = OsStr::new(&path).encode_wide().chain(Some(0)).collect();
    let mut volume_name = [0u16; 256];
    let mut fs_name = [0u16; 256];
    let mut serial_number = 0u32;
    let mut max_comp_len = 0u32;
    let mut fs_flags = 0u32;

    let res = unsafe {
        GetVolumeInformationW(
            PCWSTR(wide.as_ptr()),
            Some(&mut volume_name),
            Some(&mut serial_number),
            Some(&mut max_comp_len),
            Some(&mut fs_flags),
            Some(&mut fs_name),
        )
    };

    if res.is_err() {
        return Ok(false);
    }

    if let Ok(output) = Command::new("manage-bde")
        .args(&["-status", drive_letter])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.contains("Protection On")
            || stdout.contains("Percentage Encrypted")
            || stdout.contains("Fully Encrypted")
        {
            return Ok(true);
        }
    }

    Ok(false)
}

/// Check if the system drive is locked with BitLocker
pub fn is_system_drive_locked_with_bitlocker() -> Result<bool, WinAuditError> {
    unsafe {
        let mut buffer = [0u16; 260];
        let len = GetWindowsDirectoryW(Some(&mut buffer[..])) as usize;

        let drive_letter = if len == 0 || len >= buffer.len() {
            "C:".to_string()
        } else {
            format!("{}:", char::from_u32(buffer[0] as u32).unwrap_or('C'))
        };

        is_drive_locked_with_bitlocker(&drive_letter)
    }
}

/// This check is SMBv1 enabled
///
/// This critical for security! Because have dangerous exploit `EternalBlue`
pub fn is_smbv1_enabled() -> Result<bool, WinAuditError> {
    use windows::Win32::System::Registry::HKEY;
    unsafe {
        let hklm = HKEY_LOCAL_MACHINE;

        const CHECKS: &[(&str, &str)] = &[
            (
                "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters",
                "SMB1",
            ),
            ("SYSTEM\\CurrentControlSet\\Services\\mrxsmb10", "Start"),
        ];

        for (subkey_str, value_name_str) in CHECKS {
            let subkey: Vec<u16> = subkey_str.encode_utf16().chain(Some(0)).collect();
            let mut key = windows::Win32::System::Registry::HKEY::default();
            let open_res = RegOpenKeyExW(
                HKEY(hklm),
                PCWSTR(subkey.as_ptr()),
                Some(0),
                REG_SAM_FLAGS(KEY_READ),
                &mut key,
            );
            if open_res != WIN32_ERROR(0) {
                continue;
            }

            let value_name: Vec<u16> = value_name_str.encode_utf16().chain(Some(0)).collect();
            let mut data: u32 = 0;
            let mut size: u32 = std::mem::size_of::<u32>() as u32;

            let get_res = RegGetValueW(
                key,
                PCWSTR(std::ptr::null()),
                PCWSTR(value_name.as_ptr()),
                RRF_RT_REG_DWORD,
                None,
                Some(&mut data as *mut _ as *mut _),
                Some(&mut size),
            );

            if get_res == WIN32_ERROR(0) && data != 0 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Latest SMB version constant
pub const LATEST_SMB_VERSION: f32 = 3.1;

pub fn is_smb_version_latest() -> Result<bool, WinAuditError> {
    use windows::Win32::System::Registry::HKEY;
    unsafe {
        let hklm = HKEY_LOCAL_MACHINE;

        let server_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut server_key = windows::Win32::System::Registry::HKEY::default();
        let open_server_res = RegOpenKeyExW(
            HKEY(hklm),
            PCWSTR(server_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut server_key,
        );
        win32_to_audit_error(open_server_res, "RegOpenKeyExW (LanmanServer Parameters)")?;

        let value_name: Vec<u16> = "SMB2".encode_utf16().chain(Some(0)).collect();
        let mut smb2: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        let get_smb2_res = RegGetValueW(
            server_key,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut smb2 as *mut _ as *mut _),
            Some(&mut size),
        );

        if get_smb2_res == WIN32_ERROR(0) && smb2 != 0 {
            return Ok(true);
        }

        let client_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\mrxsmb20"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut client_key = windows::Win32::System::Registry::HKEY::default();
        let open_client_res = RegOpenKeyExW(
            HKEY(hklm),
            PCWSTR(client_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut client_key,
        );
        win32_to_audit_error(open_client_res, "RegOpenKeyExW (mrxsmb20)")?;

        let value_name_start: Vec<u16> = "Start".encode_utf16().chain(Some(0)).collect();
        let mut start: u32 = 0;
        let mut start_size: u32 = std::mem::size_of::<u32>() as u32;
        let get_start_res = RegGetValueW(
            client_key,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name_start.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut start as *mut _ as *mut _),
            Some(&mut start_size),
        );

        if get_start_res == WIN32_ERROR(0) && start != 0 {
            return Ok(true);
        }

        Ok(false)
    }
}

/// Check is the SMB server allow anonymous login, No username or password
pub fn is_smb_server_allow_anonymous_login() -> Result<bool, WinAuditError> {
    unsafe {
        let hklm = HKEY_LOCAL_MACHINE;

        let restrict_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut hkey = windows::Win32::System::Registry::HKEY::default();
        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(hklm),
            PCWSTR(restrict_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );
        win32_to_audit_error(open_res, "RegOpenKeyExW (RestrictAnonymous)")?;

        let value_name: Vec<u16> = "RestrictAnonymous".encode_utf16().chain(Some(0)).collect();
        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;
        let get_res = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );
        win32_to_audit_error(get_res, "RegGetValueW (RestrictAnonymous)")?;

        if data == 0 {
            return Ok(true);
        }

        let shares_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Shares"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut shares_key = windows::Win32::System::Registry::HKEY::default();
        let open_shares_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(hklm),
            PCWSTR(shares_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut shares_key,
        );
        if open_shares_res == WIN32_ERROR(0) {
            let mut index: u32 = 0;
            loop {
                let mut name_buffer = [0u16; 256];
                let mut name_size = name_buffer.len() as u32;
                let enum_res = RegEnumValueW(
                    shares_key,
                    index,
                    Some(PWSTR(name_buffer.as_mut_ptr())),
                    &mut name_size,
                    None,
                    None,
                    None,
                    None,
                );

                if enum_res != WIN32_ERROR(0) {
                    break;
                }

                let share_name = String::from_utf16_lossy(&name_buffer[..name_size as usize]);
                if !share_name.is_empty() {
                    return Ok(true);
                }

                index += 1;
            }
        }

        Ok(false)
    }
}

/// Check is Autorun/Autoplay enabled,
///
/// This important to Security! malicious USBS can deploy malwares automatically and silently
pub fn is_autorun_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let hives = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER];

        let keys = &[
            (
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "NoDriveTypeAutoRun",
            ),
            (
                "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer",
                "NoDriveAutoRun",
            ),
        ];

        for &hive in &hives {
            for (subkey_str, value_name_str) in keys {
                let mut hkey = windows::Win32::System::Registry::HKEY::default();

                let subkey: Vec<u16> = subkey_str.encode_utf16().chain(Some(0)).collect();
                let open_res = RegOpenKeyExW(
                    windows::Win32::System::Registry::HKEY(hive),
                    PCWSTR(subkey.as_ptr()),
                    Some(0),
                    REG_SAM_FLAGS(KEY_READ),
                    &mut hkey,
                );

                if open_res != WIN32_ERROR(0) {
                    continue;
                }

                let value_name: Vec<u16> = value_name_str.encode_utf16().chain(Some(0)).collect();
                let mut data: u32 = 0;
                let mut size: u32 = std::mem::size_of::<u32>() as u32;

                let get_res = RegGetValueW(
                    hkey,
                    PCWSTR(std::ptr::null()),
                    PCWSTR(value_name.as_ptr()),
                    RRF_RT_REG_DWORD,
                    None,
                    Some(&mut data as *mut _ as *mut _),
                    Some(&mut size),
                );

                if get_res != WIN32_ERROR(0) {
                    continue;
                }

                if data == 0 {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }
}

const FSCTL_GET_QUOTA_INFORMATION: u32 = 0x00090200;

#[repr(C)]
#[derive(Default)]
struct DISK_QUOTA_INFORMATION {
    used_space: u64,
    quota_limit: u64,
    threshold: u64,
    sid_length: u32,
    sid_offset: u32,
}

/// This check is quota enabled for specific Driver in current use scope.
///
/// enabling Quota are critical for security, prevent malicious users to exhaust the disk
pub fn is_quota_enabled_for(drive_letter: &str) -> Result<bool, WinAuditError> {
    unsafe {
        let path_str = format!(r"\\.\{}", drive_letter.trim_end_matches(['\\', ':']));
        let path: Vec<u16> = OsStr::new(&path_str)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let handle = match CreateFileW(
            PCWSTR(path.as_ptr()),
            FILE_READ_ATTRIBUTES.0 as u32,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS,
            None,
        ) {
            Ok(h) => h,
            Err(err) => {
                return Err(WinAuditError::WinAuditError {
                    failed_audit: "CreateFileW failed for drive",
                    source: err.into(),
                });
            }
        };

        if handle == INVALID_HANDLE_VALUE {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "CreateFileW returned INVALID_HANDLE_VALUE",
                source: windows_core::Error::new(
                    windows_core::HRESULT(0),
                    "Invalid handle returned",
                ),
            });
        }

        let mut quota_info = DISK_QUOTA_INFORMATION::default();
        let mut bytes_returned = 0u32;

        let success = DeviceIoControl(
            handle,
            FSCTL_GET_QUOTA_INFORMATION,
            std::ptr::null(),
            0,
            &mut quota_info as *mut _ as *mut _,
            std::mem::size_of::<DISK_QUOTA_INFORMATION>() as u32,
            &mut bytes_returned,
            std::ptr::null_mut(),
        );

        let _ = CloseHandle(handle);

        if success == 0 {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "DeviceIoControl(FSCTL_GET_QUOTA_INFORMATION) failed",
                source: windows_core::Error::new(
                    windows_core::HRESULT(0),
                    "Failed to query quota info",
                ),
            });
        }

        Ok(bytes_returned > 0)
    }
}

/// Check if the system has an account lockout policy enabled.
/// This important! for prevent brute force attacks against the target account
pub fn is_account_lockout_policy_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut buffer: *mut core::ffi::c_void = std::ptr::null_mut();

        let status = NetUserModalsGet(PCWSTR::null(), 3, &mut buffer as *mut *mut _ as *mut *mut _);

        if status != NERR_Success {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "NetUserModalsGet (Account Lockout Policy)",
                source: WIN32_ERROR(status as u32).into(),
            });
        }

        if buffer.is_null() {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "NetUserModalsGet returned NULL buffer",
                source: windows_core::Error::new(
                    windows_core::HRESULT(0),
                    "NetUserModalsGet returned NULL buffer",
                ),
            });
        }

        let info = &*(buffer as *const USER_MODALS_INFO_3);
        let threshold = info.usrmod3_lockout_threshold;

        let _ = NetApiBufferFree(Some(buffer as *mut _));

        Ok(threshold > 0)
    }
}

const CLSID_UPDATE_SESSION: GUID = GUID::from_u128(0x4cb43d7f_7eee_4906_8698_60da1c38f2fe);

/// Check is update available in Windows Update
/// This important!, Updates includes bugs and vulnerability fixes
pub fn is_update_available() -> Result<bool, WinAuditError> {
    unsafe {
        hresult_to_audit_error(
            CoInitializeEx(Some(std::ptr::null_mut()), COINIT_APARTMENTTHREADED),
            "CoInitializeEx",
        )?;

        #[allow(unused_assignments)]
        let mut updates_available = false;

        let session: WinResult<IUpdateSession> =
            CoCreateInstance(&CLSID_UPDATE_SESSION, None, CLSCTX_INPROC_SERVER);

        let session = session.map_err(|e| WinAuditError::WinAuditError {
            failed_audit: "Create UpdateSession",
            source: e.into(),
        })?;

        let searcher =
            session
                .CreateUpdateSearcher()
                .map_err(|e| WinAuditError::WinAuditError {
                    failed_audit: "Create UpdateSearcher",
                    source: e.into(),
                })?;

        let criteria = BSTR::from("IsInstalled=0 and Type='Software' and IsHidden=0");

        let search_result =
            searcher
                .Search(&criteria)
                .map_err(|e| WinAuditError::WinAuditError {
                    failed_audit: "Search Windows Update",
                    source: e.into(),
                })?;

        let count = search_result
            .Updates()
            .and_then(|u| u.Count())
            .map_err(|e| WinAuditError::WinAuditError {
                failed_audit: "Get Update count",
                source: e.into(),
            })?;

        updates_available = count > 0;

        CoUninitialize();

        Ok(updates_available)
    }
}

/// Check is bluetooth enabled
/// This improve security because Bluetooth vulnerable to huge of attacks like `BlueJacking` and other
pub fn is_bluetooth_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut params = BLUETOOTH_FIND_RADIO_PARAMS {
            dwSize: std::mem::size_of::<BLUETOOTH_FIND_RADIO_PARAMS>() as u32,
        };

        let mut radio_handle: HANDLE = HANDLE(std::ptr::null_mut());

        let find_handle = BluetoothFindFirstRadio(&mut params, &mut radio_handle).map_err(|e| {
            WinAuditError::WinAuditError {
                failed_audit: "Bluetooth FindFirstRadio",
                source: e.into(),
            }
        })?;

        if find_handle.is_invalid() || radio_handle.is_invalid() {
            return Ok(false);
        }

        let mut radio_info: BLUETOOTH_RADIO_INFO = std::mem::zeroed();
        radio_info.dwSize = std::mem::size_of::<BLUETOOTH_RADIO_INFO>() as u32;

        let win_result = BluetoothGetRadioInfo(radio_handle, &mut radio_info);

        if win_result != 0 {
            return Err(WinAuditError::WinAuditError {
                failed_audit: "Bluetooth GetRadioInfo",
                source: WIN32_ERROR(win_result).into(),
            });
        }

        let enabled = !radio_info.szName.is_empty();

        let _ = CloseHandle(radio_handle);
        let _ = BluetoothFindRadioClose(find_handle);

        Ok(enabled)
    }
}

/// Check is password policy is enforced
///
/// This important for security! Because some accounts has weak passwords
pub fn is_strong_password_policy_enforced() -> Result<bool, WinAuditError> {
    use windows::Win32::System::Registry::HKEY;
    unsafe {
        let mut min_length: u32 = 0;
        let mut min_length_size = std::mem::size_of::<u32>() as u32;

        let path_min_length: Vec<u16> = "SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let name_min_length: Vec<u16> = "MinimumPasswordLength"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let len_win_result = RegGetValueW(
            HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(path_min_length.as_ptr()),
            PCWSTR(name_min_length.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut min_length as *mut _ as *mut _),
            Some(&mut min_length_size),
        );
        win32_to_audit_error(len_win_result, "RegGetValueW (MinimumPasswordLength)")?;

        let mut complexity: u32 = 0;
        let mut complexity_size = std::mem::size_of::<u32>() as u32;

        let path_complexity: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let name_complexity: Vec<u16> =
            "PasswordComplexity".encode_utf16().chain(Some(0)).collect();

        let comp_win_result = RegGetValueW(
            HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(path_complexity.as_ptr()),
            PCWSTR(name_complexity.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut complexity as *mut _ as *mut _),
            Some(&mut complexity_size),
        );
        win32_to_audit_error(comp_win_result, "RegGetValueW (PasswordComplexity)")?;

        Ok(complexity == 1 && min_length >= 12)
    }
}

/// Check is current Wi-Fi network encrypted
///
/// This important for security! because public wifi are security risk
pub fn is_current_wifi_network_encrypted() -> Result<bool, WinAuditError> {
    unsafe {
        let mut handle = HANDLE::default();
        let mut negotiated_version: u32 = 0;

        let result = WlanOpenHandle(2, None, &mut negotiated_version, &mut handle);
        win32_to_audit_error(WIN32_ERROR(result), "WlanOpenHandle")?;

        let mut pp_interface_list: *mut WLAN_INTERFACE_INFO_LIST = std::ptr::null_mut();
        let result = WlanEnumInterfaces(handle, None, &mut pp_interface_list);
        win32_to_audit_error(WIN32_ERROR(result), "WlanEnumInterfaces")?;

        let interface_list = &*pp_interface_list;
        if interface_list.dwNumberOfItems == 0 {
            WlanFreeMemory(pp_interface_list as _);
            WlanCloseHandle(handle, None);
            return Err(WinAuditError::CustomError {
                failed_audit: "WlanEnumInterfaces",
                message: "WlanEnumInterfaces returned no interfaces",
            });
        }

        let interface_info = &interface_list.InterfaceInfo[0];
        let mut p_connection: *mut WLAN_CONNECTION_ATTRIBUTES = std::ptr::null_mut();
        let mut data_size: u32 = 0;

        let result = WlanQueryInterface(
            handle,
            &interface_info.InterfaceGuid,
            wlan_intf_opcode_current_connection,
            None,
            &mut data_size,
            &mut p_connection as *mut _ as *mut _,
            None,
        );
        win32_to_audit_error(WIN32_ERROR(result), "WlanQueryInterface")?;

        let connection = &*p_connection;
        let security = connection.wlanSecurityAttributes;

        let encrypted = security.bSecurityEnabled.as_bool()
            && security.dot11AuthAlgorithm != DOT11_AUTH_ALGO_80211_OPEN
            && security.dot11CipherAlgorithm != DOT11_CIPHER_ALGO_NONE;

        WlanFreeMemory(p_connection as _);
        WlanFreeMemory(pp_interface_list as _);
        WlanCloseHandle(handle, None);

        Ok(encrypted)
    }
}

/// Check is Empty passwords are disallowed
///
/// This critical for security! Prevent users from creating account without passwords
pub fn is_empty_passwords_disallowed() -> Result<bool, WinAuditError> {
    use windows::Win32::System::Registry::HKEY;
    unsafe {
        const REG_PATH: &str = "SYSTEM\\CurrentControlSet\\Control\\Lsa\0";
        const VALUE_NAME: &str = "LimitBlankPasswordUse\0";

        let mut hkey: HKEY = HKEY::default();

        let open_status = RegOpenKeyExA(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCSTR(REG_PATH.as_ptr()),
            Some(0),
            windows::Win32::System::Registry::REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        win32_to_audit_error(open_status, "RegOpenKeyExA (LimitBlankPasswordUse)")?;

        let mut data: u32 = 0;
        let mut data_size = std::mem::size_of::<u32>() as u32;

        let query_status = RegQueryValueExA(
            hkey,
            PCSTR(VALUE_NAME.as_ptr()),
            None,
            None,
            Some(&mut data as *mut _ as *mut u8),
            Some(&mut data_size),
        );

        let _ = RegCloseKey(hkey);

        win32_to_audit_error(query_status, "RegQueryValueExA (LimitBlankPasswordUse)")?;

        Ok(data == 1)
    }
}

/// Check is admin account Disabled
///
/// This improve security and Reduce attack surface prevent brute force and login to it
pub fn is_admin_account_disabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut buffer: *mut USER_INFO_1 = std::ptr::null_mut();

        let admin_name: Vec<u16> = "Administrator".encode_utf16().chain(Some(0)).collect();

        let status = NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(admin_name.as_ptr()),
            1,
            &mut buffer as *mut _ as *mut _,
        );

        win32_to_audit_error(
            WIN32_ERROR(status),
            "NetUserGetInfo (Administrator account)",
        )?;

        if buffer.is_null() {
            return Err(WinAuditError::CustomError {
                failed_audit: "NetUserGetInfo (Administrator account)",
                message: "NetUserGetInfo returned null buffer for Administrator account",
            });
        }

        let info = *buffer;
        NetApiBufferFree(Some(buffer as *mut _));

        Ok(info.usri1_flags & USER_ACCOUNT_FLAGS(0x0002) != USER_ACCOUNT_FLAGS(0))
    }
}

/// Check is guest access Disabled
///
/// This important for security! prevent login to the system as guest
pub fn is_guest_account_disabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut buffer: *mut USER_INFO_1 = std::ptr::null_mut();
        let guest: Vec<u16> = "Guest".encode_utf16().chain(Some(0)).collect();

        let status = NetUserGetInfo(
            PCWSTR::null(),
            PCWSTR(guest.as_ptr()),
            1,
            &mut buffer as *mut _ as *mut _,
        );

        win32_to_audit_error(WIN32_ERROR(status as u32), "NetUserGetInfo (Guest account)")?;

        if buffer.is_null() {
            return Err(WinAuditError::CustomError {
                failed_audit: "NetUserGetInfo (Guest Account)",
                message: "NetUserGetInfo returned null buffer for Guest account",
            });
        }

        let info = *buffer;
        NetApiBufferFree(Some(buffer as *mut _));

        Ok(info.usri1_flags & USER_ACCOUNT_FLAGS(0x0002) != USER_ACCOUNT_FLAGS(0))
    }
}

/// Check is automatic update is Enabled
///
/// This very important for security! Unlike manual update you can forget them and leave your system vulnerable
pub fn is_automatic_update_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> = "Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        if open_res.0 != 0 {
            return Ok(true);
        }

        let value_name: Vec<u16> = "NoAutoUpdate".encode_utf16().chain(Some(0)).collect();

        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (NoAutoUpdate)")?;

        Ok(data == 0)
    }
}

/// Check is dump of LSASS disallowed
///
/// This very important for security! If this allowed an attacker can dump user senstive info such as (User Credentials)
pub fn is_lsass_cannot_be_dumped() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        if open_res.0 != 0 {
            return Ok(true);
        }

        let value_name: Vec<u16> = "UseLogonCredential".encode_utf16().chain(Some(0)).collect();

        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (UseLogonCredential)")?;

        Ok(data == 0)
    }
}

/// Check is NTLM Disabled
///
/// NTLM vulnerable to attacks like Pass The Hash and should be disabled.
pub fn is_ntlm_disabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\Lsa"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        win32_to_audit_error(open_res, "RegOpenKeyExW (Lsa)")?;

        let value_name: Vec<u16> = "LmCompatibilityLevel"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (LmCompatibilityLevel)")?;

        Ok(data >= 5)
    }
}

pub fn is_credential_guard_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\LSA"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        win32_to_audit_error(open_res, "RegOpenKeyExW (LSA)")?;

        let value_name: Vec<u16> = "LsaCfgFlags".encode_utf16().chain(Some(0)).collect();

        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (LsaCfgFlags)")?;

        Ok(data == 1 || data == 2)
    }
}

/// Check is Drive Signing required for loading drivers to the kernel
///
/// This very important for security! If not an attacker can deploy rootkits
pub fn is_driver_signing_required() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> = "SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        win32_to_audit_error(open_res, "RegOpenKeyExW (CodeIntegrity Config)")?;

        let value_name: Vec<u16> = "CodeIntegrityEnabled"
            .encode_utf16()
            .chain(Some(0))
            .collect();

        let mut data: u32 = 0;
        let mut size: u32 = std::mem::size_of::<u32>() as u32;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(value_name.as_ptr()),
            RRF_RT_REG_DWORD,
            None,
            Some(&mut data as *mut _ as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (CodeIntegrityEnabled)")?;

        Ok(data == 1)
    }
}

/// Check is PowerShell script signing is enabled
///
/// This prevent untrusted script from running, However an attacker can still override the behavior by adding flag -Bypass to Set-ExecutionPolicy
pub fn is_powershell_script_signing_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let mut hkey = windows::Win32::System::Registry::HKEY::default();

        let key_path: Vec<u16> =
            "SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell"
                .encode_utf16()
                .chain(Some(0))
                .collect();

        let open_res = RegOpenKeyExW(
            windows::Win32::System::Registry::HKEY(HKEY_LOCAL_MACHINE),
            PCWSTR(key_path.as_ptr()),
            Some(0),
            REG_SAM_FLAGS(KEY_READ),
            &mut hkey,
        );

        win32_to_audit_error(open_res, "RegOpenKeyExW (PowerShell Script Signing)")?;

        let name: Vec<u16> = "ExecutionPolicy".encode_utf16().chain(Some(0)).collect();

        let mut buffer = [0u16; 256];
        let mut size: u32 = buffer.len() as u32 * 2;

        let rv = RegGetValueW(
            hkey,
            PCWSTR(std::ptr::null()),
            PCWSTR(name.as_ptr()),
            REG_ROUTINE_FLAGS(0),
            None,
            Some(buffer.as_mut_ptr() as *mut _),
            Some(&mut size),
        );

        win32_to_audit_error(rv, "RegGetValueW (ExecutionPolicy)")?;

        let policy = String::from_utf16_lossy(&buffer[..(size as usize / 2)])
            .trim()
            .to_string();

        Ok(matches!(policy.as_str(), "AllSigned" | "RemoteSigned"))
    }
}

/// Check is DEP enabled
///
/// DEP is a security feature prevent malicious code from executing in some areas of system memory.
pub fn is_dep_enabled() -> Result<bool, WinAuditError> {
    unsafe {
        let process = GetCurrentProcess();

        let mut dep_flags: u32 = 0;
        let mut permanent: BOOL = BOOL(0);

        audit_try!(
            "DEP Check",
            GetProcessDEPPolicy(
                process,
                &mut dep_flags as *mut u32,
                &mut permanent as *mut BOOL
            )
        )?;

        let dep_enabled = (dep_flags & PROCESS_DEP_ENABLE.0) != 0;
        let dep_permanent = permanent.as_bool();

        Ok(dep_enabled || dep_permanent)
    }
}

/// Check is User Account Control enabled
pub fn is_uac_enabled() -> Result<bool, WinAuditError> {
    const UAC_REG_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
    const UAC_VALUE: &str = "EnableLUA";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.open_subkey_with_flags(UAC_REG_KEY, KEY_READ) {
        Ok(key) => match key.get_value::<u32, _>(UAC_VALUE) {
            Ok(val) => Ok(val != 0),
            Err(_) => Ok(false),
        },
        Err(_) => Err(WinAuditError::WinAuditError {
            failed_audit: "Failed to read UAC registry key",
            source: WinError::from_thread(),
        }),
    }
}

/// Check if Windows Sandbox is supported on this system
pub fn is_windows_sandbox_supported() -> Result<bool, WinAuditError> {
    const SANDBOX_REG_KEY: &str = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Containers\CmService";
    const SANDBOX_VALUE: &str = "HvsiEnabled";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.open_subkey_with_flags(SANDBOX_REG_KEY, KEY_READ) {
        Ok(key) => match key.get_value::<u32, _>(SANDBOX_VALUE) {
            Ok(val) => Ok(val != 0),
            Err(_) => Ok(false),
        },
        Err(_) => Ok(false),
    }
}
