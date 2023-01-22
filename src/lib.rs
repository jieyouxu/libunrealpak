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

/// Version of the Unreal `.pak` archive. Adapted from [`unpak`]'s `VersionMajor`.
///
/// [`unpak`]: https://github.com/trumank/unpak/blob/master/src/lib.rs
#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
pub enum Version {
    /// Initial version
    Initial = 1,
    /// Timestamps removed
    NoTimestamps = 2,
    /// Compression and encryption support
    CompressionEncryption = 3,
    /// Index encryption support
    IndexEncryption = 4,
    /// Offsets relative to header
    RelativeChunkOffsets = 5,
    /// Record deletion support
    DeleteRecords = 6,
    /// Include key GUID
    EncryptionKeyGUID = 7,
    /// Compression names included
    FNameBasedCompression = 8,
    /// TODO: what's the difference between V8A and V8B?
    FrozenIndex = 9,
    /// Frozen index byte included
    PathHashIndex = 10,
    /// TODO: find out what this version changed
    Fnv64BugFix = 11,
}
