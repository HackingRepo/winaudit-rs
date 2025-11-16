use windows::Win32::System::SystemServices::*;

pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

#[allow(nonstandard_style)]
pub const StorageDeviceSecurityProperty: u32 = 8;
#[allow(nonstandard_style)]
pub const PropertyStandardQuery: u32 = 0;

#[repr(C)]
#[allow(nonstandard_style)]
pub struct STORAGE_PROPERTY_QUERY {
    #[allow(nonstandard_style)]
    pub PropertyId: u32,
    #[allow(nonstandard_style)]
    pub QueryType: u32,
    #[allow(nonstandard_style)]
    pub AdditionalParameters: [u8; 1],
}

pub const IOCTL_NDIS_QUERY_GLOBAL_STATS: u32 = 0x00170204;

pub const OID_GEN_SRIOV_CAPABLE: u32 = 0xFFA0;
