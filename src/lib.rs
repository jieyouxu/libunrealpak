use thiserror::Error;

pub const MAGIC: u32 = 0x5A6F12E1;

mod footer;

pub use footer::*;

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

        if self.major_version() >= 7 {
            // encryption uuid (16)
            size += 16;
        }

        if self.major_version() >= 4 {
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("magic mismatch: found {0}, expected {1}")]
    MagicMismatch(u32, u32),
    #[error("version mismatch: found {0}, expected {1}")]
    VersionMismatch(u32, u32),
}
