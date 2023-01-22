pub const MAGIC: u32 = 0x5A6F12E1;

/// Footer of the `.pak` archive.
#[derive(Debug, Clone, PartialEq)]
pub enum Footer {
    V3AndBelow {
        common: FooterCommon,
    },
    V4ToV6 {
        is_encrypted: bool,
        common: FooterCommon,
    },
    V7 {
        is_encrypted: bool,
        encryption_key: [u8; 20],
        common: FooterCommon,
    },
    V8 {
        is_encrypted: bool,
        encryption_key: [u8; 20],
        common: FooterCommon,
        compression_methods: [u8; 128],
    },
    V9 {
        is_encrypted: bool,
        encryption_key: [u8; 20],
        common: FooterCommon,
        is_frozen_index: bool,
        compression_methods: [u8; 160],
    },
}

/// Common footer properties shared by all known `.pak` versions.
#[derive(Debug, Clone, PartialEq)]
pub struct FooterCommon {
    pub magic: u32,
    pub version: Version,
    pub index_offset: u64,
    pub index_size: u64,
    pub index_hash: [u8; 20],
}

/// Major and minor versions of the Unreal `.pak` archive format.
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum Version {
    V1,
    V2,
    V3,
    V4,
    V5,
    V6,
    V7,
    V8A,
    V8B,
    V9,
    V10,
    V11,
}

impl Version {
    pub fn major_version(self) -> u32 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
            Self::V3 => 3,
            Self::V4 => 4,
            Self::V5 => 5,
            Self::V6 => 6,
            Self::V7 => 7,
            Self::V8A => 8,
            Self::V8B => 8,
            Self::V9 => 9,
            Self::V10 => 10,
            Self::V11 => 11,
        }
    }

    pub fn footer_size(self) -> u64 {
        // Taken verbatim from
        // <https://github.com/trumank/unpak/blob/de69a98d34d902418916d15877f595f161074147/src/lib.rs#L57>.
        let mut size = {
            // Size of common properties across all versions:
            // magic (4) + version (4) + offset (8) + size (8) + hash (20)
            4 + 4 + 8 + 8 + 20
        };

        if self.major_version() >= 4 {
            // encryption uuid (16)
            size += 16;
        }

        if self.major_version() >= 7 {
            // is encrypted (1)
            size += 1;
        }

        if self.major_version() == 9 {
            // is frozen (1)
            size += 1;
        }

        if self >= Version::V8A {
            // compression names (128)
            size += 128;
        }

        if self >= Version::V8B {
            // additional compression name (+32)
            size += 32;
        }

        size
    }
}
