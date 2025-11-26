//! A collection of important constants.

#![allow(non_snake_case)]

use pretty_hex::HexConfig;
use winapi::shared::ntdef;

use crate::{c_define, types};

pub const CLIPSP: &str = "./emu64/";

// Config
pub const PRINT_DATA: bool = false;
pub const HEX_CONFIG: HexConfig = HexConfig {
    title: true,
    ascii: false,
    width: 16,
    group: 4,
    chunk: 1,
    max_bytes: usize::MAX,
    display_offset: 0,
};

// Addresses
/// Decrypt function (Type 1)
pub const DECRYPT_1: usize = 0x1C0001158;
/// Decrypt function (Type 2)
pub const DECRYPT_2: usize = 0x1C00011E4;
pub const CONST_DATA_2: usize = 0x1C00A1D60;
pub const READ_WRITE_DATA_2: usize = 0x1C00AA8B8;
pub const CONST_DATA_3: usize = 0x1C00A1E10;
pub const READ_WRITE_DATA_3: usize = 0x1C00AA8E0;
pub const CONST_DATA_4: usize = 0x1C00A24C0;
pub const READ_WRITE_DATA_4: usize = 0x1C00AAA80;
pub const CONST_DATA_5: usize = 0x1C00A2DE0;
pub const READ_WRITE_DATA_5: usize = 0x1C00AACC0;
/// Encryption data (const data, read-write data, decrypt function, enumeration)
pub const DATA: &[(usize, usize, usize, usize)] = &[
    (CONST_DATA_2, READ_WRITE_DATA_2, DECRYPT_2, 2),
    (CONST_DATA_3, READ_WRITE_DATA_3, DECRYPT_1, 3),
    (CONST_DATA_4, READ_WRITE_DATA_4, DECRYPT_2, 4),
    (CONST_DATA_5, READ_WRITE_DATA_5, DECRYPT_1, 5),
];

// Dummy Values
/// Dummy EPROCESS. This is used for functions that require an EPROCESS value.
pub const EPROCESS: types::EPROCESS = types::EPROCESS {
    pid: 0xFEED,
};

// DLL Flags
/// https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryexw
pub const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x00000001;

// MDL Flags
c_define!{
    #[allow(overflowing_literals)]
    pub ntdef::CSHORT:
    #define MDL_MAPPED_TO_SYSTEM_VA     0x0001
    #define MDL_PAGES_LOCKED            0x0002
    #define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
    #define MDL_ALLOCATED_FIXED_SIZE    0x0008
    #define MDL_PARTIAL                 0x0010
    #define MDL_PARTIAL_HAS_BEEN_MAPPED 0x0020
    #define MDL_IO_PAGE_READ            0x0040
    #define MDL_WRITE_OPERATION         0x0080
    #define MDL_PARENT_MAPPED_SYSTEM_VA 0x0100
    #define MDL_FREE_EXTRA_PTES         0x0200
    #define MDL_DESCRIBES_AWE           0x0400
    #define MDL_IO_SPACE                0x0800
    #define MDL_NETWORK_HEADER          0x1000
    #define MDL_MAPPING_CAN_FAIL        0x2000
    #define MDL_ALLOCATED_MUST_SUCCEED  0x4000
    #define MDL_INTERNAL                0x8000
}

/// Relevant addresses where decryption occurs.
/// DO NOT CHANGE THESE. THESE DO NOTHING.
pub const UNUSED_ADDRESSES: [(usize, usize); 66] = [(0x1C003295F, 0x1C003297F), (0x1C00BA995, 0x1C00BA9AA), (0x1C00BA9CB, 0x1C00BA9E0), (0x1C00BAB38, 0x1C00BAB5E), (0x1C00BBA30, 0x1C00BBA4A), (0x1C00BBF24, 0x1C00BBF3E), (0x1C00BC001, 0x1C00BC029), (0x1C00BDF39, 0x1C00BDF4E), (0x1C00BDF54, 0x1C00BDF69), (0x1C00BE102, 0x1C00BE117), (0x1C00BE119, 0x1C00BE12E), (0x1C00BE244, 0x1C00BE259), (0x1C00BE32C, 0x1C00BE341), (0x1C00BE382, 0x1C00BE397), (0x1C00BE549, 0x1C00BE564), (0x1C00BE73E, 0x1C00BE759), (0x1C00BE96D, 0x1C00BE985), (0x1C00BEBB5, 0x1C00BEBD8), (0x1C00BED25, 0x1C00BED40), (0x1C00BEF4E, 0x1C00BEF69), (0x1C00BF124, 0x1C00BF139), (0x1C00BF1BA, 0x1C00BF1D7), (0x1C00BF29D, 0x1C00BF2B7), (0x1C00BF378, 0x1C00BF38F), (0x1C00BF54F, 0x1C00BF56A), (0x1C00BF8D5, 0x1C00BF8ED), (0x1C00BF9FF, 0x1C00BFA23), (0x1C00BFB84, 0x1C00BFB99), (0x1C00BFD95, 0x1C00BFDAA), (0x1C00BFDAC, 0x1C00BFDC1), (0x1C00BFE72, 0x1C00BFE87), (0x1C00BFFED, 0x1C00C0004), (0x1C00C00E8, 0x1C00C00FE), (0x1C00C0341, 0x1C00C0359), (0x1C00C052F, 0x1C00C0544), (0x1C00C05E1, 0x1C00C05F9), (0x1C00C074D, 0x1C00C0767), (0x1C00C1D9B, 0x1C00C1DAE), (0x1C00BA9B0, 0x1C00BA9C5), (0x1C00BAE2C, 0x1C00BAE41), (0x1C00BBA50, 0x1C00BBA65), (0x1C00BBF40, 0x1C00BBF55), (0x1C00BC02F, 0x1C00BC044), (0x1C00BC248, 0x1C00BC261), (0x1C00BE25B, 0x1C00BE270), (0x1C00BE347, 0x1C00BE35C), (0x1C00BE56A, 0x1C00BE57F), (0x1C00BE75F, 0x1C00BE774), (0x1C00BE98B, 0x1C00BE9A0), (0x1C00BEBDE, 0x1C00BEBF3), (0x1C00BED46, 0x1C00BED5B), (0x1C00BEF6F, 0x1C00BEF84), (0x1C00BF13B, 0x1C00BF150), (0x1C00BF1DD, 0x1C00BF1F2), (0x1C00BF2B9, 0x1C00BF2CE), (0x1C00BF570, 0x1C00BF585), (0x1C00BF8F3, 0x1C00BF908), (0x1C00BFA29, 0x1C00BFA3E), (0x1C00BFB9F, 0x1C00BFBB4), (0x1C00C000E, 0x1C00C0023), (0x1C00C011E, 0x1C00C0133), (0x1C00C035B, 0x1C00C0370), (0x1C00C04FC, 0x1C00C0516), (0x1C00C0518, 0x1C00C052D), (0x1C00C05FB, 0x1C00C0610), (0x1C00C0769, 0x1C00C077E)];
