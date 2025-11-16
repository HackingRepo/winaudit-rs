//! This provide Security Software Checks for windows systems
//!
use std::path::Path;
use std::process::Command;

use crate::WinError;
use winreg::RegKey;
use winreg::enums;
use winreg::enums::HKEY_LOCAL_MACHINE;
use winreg::enums::KEY_READ;

use crate::WinAuditError;

pub fn is_bitdefender_installed() -> Result<bool, WinAuditError> {
    const BITDEFENDER_KEY: &str = r"SOFTWARE\Bitdefender";
    let hklm = RegKey::predef(enums::HKEY_LOCAL_MACHINE);

    match hklm.open_subkey_with_flags(BITDEFENDER_KEY, enums::KEY_READ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

pub fn is_windows_defender_enabled() -> Result<bool, WinAuditError> {
    const WD_REG_KEY: &str = r"SOFTWARE\Microsoft\Windows Defender";
    let hklm = RegKey::predef(enums::HKEY_LOCAL_MACHINE);

    match hklm.open_subkey_with_flags(WD_REG_KEY, enums::KEY_READ) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Check if Bitdefender is installed and enabled
pub fn is_bitdefender_installed_and_enabled() -> Result<bool, WinAuditError> {
    const BITDEFENDER_KEY: &str = r"SOFTWARE\Bitdefender\Bitdefender Security";

    let hklm = RegKey::predef(enums::HKEY_LOCAL_MACHINE);

    let key = hklm
        .open_subkey_with_flags(BITDEFENDER_KEY, enums::KEY_READ)
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Bitdefender registry key not found",
            source: WinError::from_thread(),
        })?;

    let product_state: u32 = key.get_value("ProductState").unwrap_or(0);

    Ok(product_state != 0)
}

/// Check if Bitdefender Total Security is installed
pub fn is_bitdefender_total_security() -> Result<bool, WinAuditError> {
    const BITDEFENDER_TOTAL_KEY: &str = r"SOFTWARE\Bitdefender\Bitdefender Security\Total Security";

    let hklm = RegKey::predef(enums::HKEY_LOCAL_MACHINE);

    let key = hklm
        .open_subkey_with_flags(BITDEFENDER_TOTAL_KEY, enums::KEY_READ)
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Bitdefender Total Security registry key not found",
            source: WinError::from_thread(),
        })?;

    let product_state: u32 = key.get_value("ProductState").unwrap_or(0);

    Ok(product_state != 0)
}

pub fn is_wazuh_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let wazuh_path = r"C:\Program Files (x86)\ossec-agent";

    if !Path::new(wazuh_path).exists() {
        return Ok(false);
    }

    let config_file = Path::new(wazuh_path).join("ossec.conf");
    if !config_file.exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "WazuhSvc"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to check Wazuh service status",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is Norton 360 Deluxe installed
pub fn is_norton_360_deluxe_installed() -> Result<bool, WinAuditError> {
    let norton_path = r"C:\Program Files\Norton Security";

    if Path::new(norton_path).exists() {
        return Ok(true);
    }

    let output = Command::new("sc")
        .args(&["query", "NortonSecurity"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Norton service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") || stdout.contains("STOPPED") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is Norton 360 Deluxe installed and enabled
pub fn is_norton_360_deluxe_installed_and_enabled() -> Result<bool, WinAuditError> {
    let norton_path = r"C:\Program Files\Norton Security";

    if !Path::new(norton_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "NortonSecurity"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Norton service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Generic helper to check if a folder exists
fn is_program_installed(path: &str) -> bool {
    Path::new(path).exists()
}

/// Generic helper to check if a service is running
fn is_service_running(service_name: &str) -> Result<bool, WinAuditError> {
    let output = Command::new("sc")
        .args(&["query", service_name])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.contains("RUNNING"))
}

pub fn is_nord_vpn_installed() -> Result<bool, WinAuditError> {
    Ok(is_program_installed(r"C:\Program Files\NordVPN"))
}

/// Check is NordVPN installed and running properly
pub fn is_nord_vpn_installed_and_running() -> Result<bool, WinAuditError> {
    if !is_nord_vpn_installed()? {
        return Ok(false);
    }
    is_service_running("NordVPNService")
}

/// Check is ProtonVPN installed
pub fn is_proton_vpn_installed() -> Result<bool, WinAuditError> {
    Ok(is_program_installed(r"C:\Program Files\ProtonVPN"))
}

/// Check is SurfShark VPN installed
pub fn is_surfshark_vpn_installed() -> Result<bool, WinAuditError> {
    Ok(is_program_installed(r"C:\Program Files\Surfshark"))
}

/// Check is ExpressVPN installed
pub fn is_express_vpn_installed() -> Result<bool, WinAuditError> {
    Ok(is_program_installed(r"C:\Program Files\ExpressVPN"))
}

/// Chech is ExpressVPN installed and running properly
pub fn is_express_vpn_installed_and_running() -> Result<bool, WinAuditError> {
    if !is_express_vpn_installed()? {
        return Ok(false);
    }
    is_service_running("ExpressVPNService")
}

/// Check is Surfshark VPN installed and running properly
pub fn is_surfshark_vpn_installed_and_running() -> Result<bool, WinAuditError> {
    if !is_surfshark_vpn_installed()? {
        return Ok(false);
    }
    is_service_running("SurfsharkService")
}

/// Check is ProtonVPN installed and running properly
pub fn is_proton_vpn_installed_and_running() -> Result<bool, WinAuditError> {
    if !is_proton_vpn_installed()? {
        return Ok(false);
    }
    is_service_running("ProtonVPNService")
}

/// Check if the OSSEC agent is installed and running
pub fn is_ossec_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\ossec-agent",
        r"C:\Program Files (x86)\ossec-agent",
    ];

    let installed = paths.iter().any(|p| Path::new(p).exists());
    if !installed {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "ossecsvc"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query OSSEC service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.contains("RUNNING"))
}

/// Check is ThreatLocker agent installed and configured
pub fn is_threatlocker_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let possible_paths = [
        r"C:\Program Files\ThreatLocker",
        r"C:\Program Files (x86)\ThreatLocker",
    ];

    let installed = possible_paths.iter().any(|p| Path::new(p).exists());
    if !installed {
        return Ok(false);
    }
    let output = Command::new("sc")
        .args(&["query", "ThreatLockerService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query ThreatLocker service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    Ok(stdout.contains("RUNNING"))
}

/// Check if the CrowdStrike Falcon agent is installed and configured.
pub fn is_crowdstrike_falcon_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let falcon_path = r"C:\Program Files\CrowdStrike";

    if !Path::new(falcon_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "CSFalconService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query CrowdStrike Falcon service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is Cloudflare Warp installed and running
pub fn is_cloudflare_warp_installed_and_running() -> Result<bool, WinAuditError> {
    let warp_path = r"C:\Program Files\Cloudflare\Cloudflare WARP";

    if !Path::new(warp_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "CloudflareWARP"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Cloudflare WARP service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is SentinelOne Agent installed and configured
pub fn is_sentinelone_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let s1_path = r"C:\Program Files\SentinelOne";

    if !Path::new(s1_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "SentinelAgent"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query SentinelOne service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is Vmware Carbon Black Agent installed and configured
pub fn is_carbon_black_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let cb_path = r"C:\Program Files\CarbonBlack";

    if !Path::new(cb_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "CbDefense"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Carbon Black service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is BitDefender GravityZone Agent installed and configured
pub fn is_bitdefender_gravityzone_agent_installed() -> Result<bool, WinAuditError> {
    let gz_path = r"C:\Program Files\Bitdefender\Endpoint Security";

    if !Path::new(gz_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "EPIntegrationService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query GravityZone service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if NordLayer is installed and running properly
pub fn is_nordlayer_installed_and_running() -> Result<bool, WinAuditError> {
    let nordlayer_path = r"C:\Program Files\NordLayer";

    if !Path::new(nordlayer_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "NordLayerService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query NordLayer service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if Sophos antivirus is Installed and Enabled
pub fn is_sophos_antivirus_installed_and_enabled() -> Result<bool, WinAuditError> {
    let sophos_path = r"C:\Program Files\Sophos\Sophos Anti-Virus";

    if !Path::new(sophos_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "SAVService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Sophos Antivirus service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if stdout.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check if Sophos InterceptX agent is installed and configured
pub fn is_sophos_interceptx_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\Sophos\Endpoint Agent",
        r"C:\Program Files\Sophos\Intercept X",
    ];

    // Check installation directories
    let mut installed = false;
    for p in &paths {
        if Path::new(p).exists() {
            installed = true;
            break;
        }
    }

    if !installed {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "Sophos Endpoint Defense Service"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Sophos Intercept X core service",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !stdout.contains("RUNNING") {
        return Ok(false);
    }

    let output2 = Command::new("sc")
        .args(&["query", "Sophos Device Control Service"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query Sophos Tamper Protection service",
            source: WinError::from_thread(),
        })?;

    let stdout2 = String::from_utf8_lossy(&output2.stdout);

    if stdout2.contains("RUNNING") {
        Ok(true)
    } else {
        Ok(false)
    }
}

pub fn is_malwarebytes_antivirus_installed_and_enabled() -> Result<bool, WinAuditError> {
    let install_path = r"C:\Program Files\Malwarebytes\Anti-Malware";
    if !Path::new(install_path).exists() {
        return Ok(false);
    }

    let output = Command::new("sc")
        .args(&["query", "MBAMService"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query MBAMService",
            source: WinError::from_thread(),
        })?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    if !stdout.contains("RUNNING") {
        return Ok(false);
    }

    let output_web = Command::new("sc")
        .args(&["query", "MBWebProtection"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query MBWebProtection",
            source: WinError::from_thread(),
        })?;

    let stdout_web = String::from_utf8_lossy(&output_web.stdout);
    let web_running = stdout_web.contains("RUNNING");

    let output_exploit = Command::new("sc")
        .args(&["query", "MBAMChameleon"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query MBAMChameleon",
            source: WinError::from_thread(),
        })?;

    let stdout_exploit = String::from_utf8_lossy(&output_exploit.stdout);
    let exploit_running = stdout_exploit.contains("RUNNING");

    if web_running || exploit_running {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is MalwareBytes endpoint Agent installed and configured
pub fn is_malwarebytes_endpoint_agent_installed_and_configured() -> Result<bool, WinAuditError> {
    const POSSIBLE_PATHS: &[&str] = &[
        r"C:\Program Files\Malwarebytes Endpoint Agent",
        r"C:\Program Files\Malwarebytes\Endpoint Agent",
        r"C:\Program Files\Malwarebytes\Nebula Agent",
    ];

    let mut installed = false;
    for path in POSSIBLE_PATHS {
        if Path::new(path).exists() {
            installed = true;
            break;
        }
    }

    if !installed {
        return Ok(false);
    }

    fn service_running(name: &str) -> Result<bool, WinAuditError> {
        let output = Command::new("sc")
            .args(&["query", name])
            .output()
            .map_err(|_| WinAuditError::WinAuditError {
                failed_audit: "Failed to query Malwarebytes Endpoint Agent service",
                source: WinError::from_thread(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains("RUNNING"))
    }

    let core_running = service_running("MBEndpointAgent")?;
    if !core_running {
        return Ok(false);
    }

    let endpoint_service_running = service_running("MBEndpointService")?;
    let defense_running = service_running("MBEndpointDefense")?;

    if endpoint_service_running || defense_running {
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Check is Manage Engine Endpoint Agent Installed and Configured
pub fn is_manage_engine_endpoint_central_agent_installed_and_configured()
-> Result<bool, WinAuditError> {
    const POSSIBLE_PATHS: &[&str] = &[
        r"C:\Program Files\ManageEngine\UEMS_Agent",
        r"C:\Program Files (x86)\ManageEngine\UEMS_Agent",
        r"C:\Program Files\DesktopCentral_Agent",
        r"C:\Program Files (x86)\DesktopCentral_Agent",
    ];

    let mut installed = false;
    for p in POSSIBLE_PATHS {
        if Path::new(p).exists() {
            installed = true;
            break;
        }
    }

    if !installed {
        return Ok(false);
    }

    fn service_running(svc: &str) -> Result<bool, WinAuditError> {
        let output = Command::new("sc")
            .args(&["query", svc])
            .output()
            .map_err(|_| WinAuditError::WinAuditError {
                failed_audit: "Failed to query ManageEngine service",
                source: WinError::from_thread(),
            })?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.contains("RUNNING"))
    }

    let core_services = [
        "MEUEMSAgent",
        "ManageEngine UEMS Agent",
        "MEAgent",
        "ManageEngine Desktop Central - Agent",
    ];

    let mut any_running = false;
    for svc in core_services {
        if service_running(svc)? {
            any_running = true;
            break;
        }
    }

    if !any_running {
        return Ok(false);
    }

    let reg_path = r"HKLM\SOFTWARE\ManageEngine\UEMS_Agent";
    let reg_query = Command::new("reg")
        .args(&["query", reg_path, "/v", "AgentServerName"])
        .output()
        .map_err(|_| WinAuditError::WinAuditError {
            failed_audit: "Failed to query ManageEngine registry configuration",
            source: WinError::from_thread(),
        })?;

    let reg_stdout = String::from_utf8_lossy(&reg_query.stdout);

    if !reg_stdout.contains("AgentServerName") {
        return Ok(false);
    }

    Ok(true)
}

/// Check is wireshark installed
pub fn is_wireshark_installed() -> Result<bool, WinAuditError> {
    let common_paths = [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
    ];

    for path in &common_paths {
        if Path::new(path).exists() {
            return Ok(true);
        }
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let uninstall = hklm.open_subkey_with_flags(
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ,
    );

    if let Ok(key) = uninstall {
        for entry in key.enum_keys().flatten() {
            if entry.to_lowercase().contains("wireshark") {
                return Ok(true);
            }
        }
    }

    let uninstall_wow = hklm.open_subkey_with_flags(
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        KEY_READ,
    );

    if let Ok(key) = uninstall_wow {
        for entry in key.enum_keys().flatten() {
            if entry.to_lowercase().contains("wireshark") {
                return Ok(true);
            }
        }
    }

    let cmd = Command::new("where").arg("tshark").output();

    if let Ok(output) = cmd {
        let stdout = String::from_utf8_lossy(&output.stdout);
        if stdout.to_lowercase().contains("tshark") {
            return Ok(true);
        }
    }

    Ok(false)
}

pub fn is_bitdefender_total_security_and_not_eol() -> Result<bool, WinAuditError> {
    const KEY: &str = r"SOFTWARE\Bitdefender\Bitdefender Security\Total Security";
    const MIN_VERSION: &str = "25.0.0";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let key =
        hklm.open_subkey_with_flags(KEY, KEY_READ)
            .map_err(|_| WinAuditError::WinAuditError {
                failed_audit: "Bitdefender Total Security registry key not found",
                source: WinError::from_thread(),
            })?;

    let product_state: u32 = key.get_value("ProductState").unwrap_or(0);
    if product_state == 0 {
        return Ok(false);
    }

    let version: String = key.get_value("ProductVersion").unwrap_or_default();
    Ok(version >= MIN_VERSION.to_string())
}

pub fn is_norton_360_deluxe_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Norton Security";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("NortonSecurity")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\NortonLifeLock\Norton Security") {
        let version: String = key.get_value("ProductVersion").unwrap_or_default();
        return Ok(version >= "22.20.0".to_string());
    }

    Ok(false)
}

pub fn is_malwarebytes_antivirus_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Malwarebytes\Anti-Malware";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !(is_service_running("MBAMService")?
        || is_service_running("MBWebProtection")?
        || is_service_running("MBAMChameleon")?)
    {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Malwarebytes\Malwarebytes Anti-Malware") {
        let version: String = key.get_value("ProductVersion").unwrap_or_default();
        return Ok(version >= "4.5.0".to_string());
    }

    Ok(false)
}

pub fn is_sophos_antivirus_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Sophos\Sophos Anti-Virus";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("SAVService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Sophos\Sophos Anti-Virus") {
        let version: String = key.get_value("ProductVersion").unwrap_or_default();
        return Ok(version >= "10.0.0".to_string());
    }

    Ok(false)
}

pub fn is_ossec_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\ossec-agent",
        r"C:\Program Files (x86)\ossec-agent",
    ];
    let installed_path = paths.iter().find(|p| Path::new(p).exists());
    let installed_path = match installed_path {
        Some(p) => p,
        None => return Ok(false),
    };

    if !is_service_running("ossecsvc")? {
        return Ok(false);
    }

    let conf_path = Path::new(installed_path).join("ossec.conf");
    let content = std::fs::read_to_string(conf_path).unwrap_or_default();
    let version_line = content.lines().find(|l| l.contains("<ossec_version>"));
    if let Some(line) = version_line {
        let version = line
            .trim()
            .replace("<ossec_version>", "")
            .replace("</ossec_version>", "");
        return Ok(version >= "4.3.0".to_string());
    }

    Ok(false)
}

pub fn is_nord_vpn_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\NordVPN";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("NordVPNService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\NordVPN") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "7.0.0".to_string());
    }

    Ok(false)
}

pub fn is_express_vpn_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\ExpressVPN";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("ExpressVPNService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\ExpressVPN") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "12.0.0".to_string());
    }

    Ok(false)
}

pub fn is_surfshark_vpn_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Surfshark";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("SurfsharkService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Surfshark") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "5.0.0".to_string());
    }

    Ok(false)
}

pub fn is_proton_vpn_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\ProtonVPN";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("ProtonVPNService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\ProtonVPN") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "3.0.0".to_string());
    }

    Ok(false)
}

pub fn is_nordlayer_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\NordLayer";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("NordLayerService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\NordLayer") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "4.0.0".to_string());
    }

    Ok(false)
}

pub fn is_wireshark_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\Wireshark\Wireshark.exe",
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files\Wireshark",
        r"C:\Program Files (x86)\Wireshark",
    ];

    if !paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Wireshark") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "4.0.0".to_string());
    }

    Ok(false)
}

pub fn is_manage_engine_endpoint_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\ManageEngine\UEMS_Agent",
        r"C:\Program Files (x86)\ManageEngine\UEMS_Agent",
        r"C:\Program Files\DesktopCentral_Agent",
        r"C:\Program Files (x86)\DesktopCentral_Agent",
    ];

    if !paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    let services = [
        "MEUEMSAgent",
        "ManageEngine UEMS Agent",
        "MEAgent",
        "ManageEngine Desktop Central - Agent",
    ];
    if !services
        .iter()
        .any(|s| is_service_running(s).unwrap_or(false))
    {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\ManageEngine\UEMS_Agent") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "10.0.0".to_string());
    }

    Ok(false)
}

pub fn is_malwarebytes_endpoint_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\Malwarebytes Endpoint Agent",
        r"C:\Program Files\Malwarebytes\Endpoint Agent",
        r"C:\Program Files\Malwarebytes\Nebula Agent",
    ];

    if !paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    let services = ["MBEndpointAgent", "MBEndpointService", "MBEndpointDefense"];
    if !services
        .iter()
        .any(|s| is_service_running(s).unwrap_or(false))
    {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Malwarebytes\Endpoint Agent") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "3.0.0".to_string());
    }

    Ok(false)
}

pub fn is_sophos_interceptx_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\Sophos\Endpoint Agent",
        r"C:\Program Files\Sophos\Intercept X",
    ];

    if !paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    let services = [
        "Sophos Endpoint Defense Service",
        "Sophos Device Control Service",
    ];
    if !services
        .iter()
        .all(|s| is_service_running(s).unwrap_or(false))
    {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Sophos\Intercept X") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "10.0.0".to_string());
    }

    Ok(false)
}

pub fn is_bitdefender_gravityzone_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Bitdefender\Endpoint Security";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("EPIntegrationService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Bitdefender\Endpoint Security") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "7.0.0".to_string());
    }

    Ok(false)
}

pub fn is_cloudflare_warp_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\Cloudflare\Cloudflare WARP";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("CloudflareWARP")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\Cloudflare\Cloudflare WARP") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "2023.0.0".to_string());
    }

    Ok(false)
}

pub fn is_carbon_black_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\CarbonBlack";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("CbDefense")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\CarbonBlack\CbDefense") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "7.0.0".to_string());
    }

    Ok(false)
}

pub fn is_sentinelone_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\SentinelOne";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("SentinelAgent")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\SentinelOne") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "22.0.0".to_string());
    }

    Ok(false)
}

pub fn is_crowdstrike_falcon_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let path = r"C:\Program Files\CrowdStrike";
    if !Path::new(path).exists() {
        return Ok(false);
    }

    if !is_service_running("CSFalconService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\CrowdStrike\Falcon") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "7.40.0".to_string());
    }

    Ok(false)
}

pub fn is_threatlocker_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let paths = [
        r"C:\Program Files\ThreatLocker",
        r"C:\Program Files (x86)\ThreatLocker",
    ];

    if !paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    if !is_service_running("ThreatLockerService")? {
        return Ok(false);
    }

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(key) = hklm.open_subkey(r"SOFTWARE\ThreatLocker") {
        let version: String = key.get_value("Version").unwrap_or_default();
        return Ok(version >= "3.0.0".to_string());
    }

    Ok(false)
}

pub fn is_wazuh_agent_installed_and_not_eol() -> Result<bool, WinAuditError> {
    let wazuh_paths = [
        r"C:\Program Files\ossec-agent",
        r"C:\Program Files (x86)\ossec-agent",
    ];

    if !wazuh_paths.iter().any(|p| Path::new(p).exists()) {
        return Ok(false);
    }

    let config_file = Path::new(wazuh_paths[0]).join("ossec.conf");
    if !config_file.exists() {
        return Ok(false);
    }

    if !is_service_running("WazuhSvc")? {
        return Ok(false);
    }

    use std::fs;
    if let Ok(contents) = fs::read_to_string(config_file) {
        if let Some(ver_line) = contents.lines().find(|l| l.contains("<version>")) {
            let ver = ver_line
                .replace("<version>", "")
                .replace("</version>", "")
                .trim()
                .to_string();
            return Ok(ver >= "4.4.0".to_string());
        }
    }

    Ok(false)
}

pub fn is_windows_defender_not_eol() -> Result<bool, WinAuditError> {
    const WD_REG_KEY: &str = r"SOFTWARE\Microsoft\Windows Defender";

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    let key = match hklm.open_subkey_with_flags(WD_REG_KEY, KEY_READ) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };

    let enabled: u32 = key.get_value("DisableAntiSpyware").unwrap_or(0);
    if enabled != 0 {
        return Ok(false);
    }

    let version: String = key.get_value("ProductVersion").unwrap_or_default();
    Ok(version >= "4.18.2305".to_string())
}
