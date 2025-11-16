#[cfg(not(target_os = "windows"))]
compile_error!("This module only for windows os");

pub mod hardwarechecks;
pub mod oschecks;
pub mod softwarechecks;

use std::fmt;
use windows::core::BOOL;
use windows::core::HRESULT;
pub(crate) use windows::{Win32::Foundation::WIN32_ERROR, core::Error as WinError};

/// An error for failed windows security audit
#[derive(Debug)]
pub enum WinAuditError {
    WinAuditError {
        failed_audit: &'static str,
        source: WinError,
    },
    CustomError {
        failed_audit: &'static str,
        message: &'static str,
    },
}

impl Default for WinAuditError {
    fn default() -> Self {
        Self::CustomError {
            failed_audit: "Unknown audit",
            message: "Default Error Message",
        }
    }
}

impl fmt::Display for WinAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WinAuditError::WinAuditError {
                failed_audit,
                source,
            } => {
                write!(f, "[{}] Windows API error: {}", failed_audit, source)
            }
            WinAuditError::CustomError {
                failed_audit,
                message,
            } => {
                write!(f, "[{}] {}", failed_audit, message)
            }
        }
    }
}

impl std::error::Error for WinAuditError {}
impl From<WinError> for WinAuditError {
    fn from(err: WinError) -> Self {
        WinAuditError::WinAuditError {
            failed_audit: "Unknown audit",
            source: err,
        }
    }
}

impl From<&'static str> for WinAuditError {
    fn from(err: &'static str) -> Self {
        WinAuditError::CustomError {
            failed_audit: "Unknown Audit",
            message: err,
        }
    }
}

impl From<i32> for WinAuditError {
    fn from(code: i32) -> Self {
        WinAuditError::WinAuditError {
            failed_audit: "Unknown Audit",
            source: std::io::Error::from_raw_os_error(code).into(),
        }
    }
}

impl From<u32> for WinAuditError {
    fn from(code: u32) -> Self {
        WinAuditError::WinAuditError {
            failed_audit: "Unknown Audit",
            source: std::io::Error::from_raw_os_error(code as i32).into(),
        }
    }
}

impl From<WIN32_ERROR> for WinAuditError {
    fn from(value: WIN32_ERROR) -> Self {
        WinAuditError::WinAuditError {
            failed_audit: "Unknown Audit",
            source: std::io::Error::from_raw_os_error(value.0 as i32).into(),
        }
    }
}
impl From<HRESULT> for WinAuditError {
    fn from(value: HRESULT) -> Self {
        WinAuditError::WinAuditError {
            failed_audit: "Unknown Audit",
            source: std::io::Error::from_raw_os_error(value.0).into(),
        }
    }
}

impl Into<WIN32_ERROR> for WinAuditError {
    fn into(self) -> WIN32_ERROR {
        match self {
            WinAuditError::WinAuditError { source, .. } => WIN32_ERROR(source.code().0 as u32),
            WinAuditError::CustomError { .. } => WIN32_ERROR(1),
        }
    }
}
impl Into<BOOL> for WinAuditError {
    fn into(self) -> BOOL {
        BOOL(self.as_bool() as i32)
    }
}

impl WinAuditError {
    fn as_bool(&self) -> bool {
        match self {
            WinAuditError::WinAuditError { .. } => false,
            WinAuditError::CustomError { .. } => false,
        }
    }
}

/// A helper to convert os errors to WinAuditError type
pub(crate) fn win32_to_audit_error(
    code: WIN32_ERROR,
    audit: &'static str,
) -> Result<(), WinAuditError> {
    if code == WIN32_ERROR(0) {
        Ok(())
    } else {
        Err(WinAuditError::WinAuditError {
            failed_audit: audit,
            source: code.into(),
        })
    }
}

pub(crate) fn hresult_to_audit_error(
    hr: HRESULT,
    audit: &'static str,
) -> Result<(), WinAuditError> {
    if hr.is_ok() {
        Ok(())
    } else {
        Err(WinAuditError::WinAuditError {
            failed_audit: audit,
            source: hr.into(),
        })
    }
}
