use std::slice::Iter;

#[derive(Debug, Copy, Clone, PartialEq, PartialOrd)]
#[repr(u32)]
pub enum VersionMajor {
    Unknown = 0,               // v0 unknown (mostly just for padding)
    Initial = 1,               // v1 initial specification
    NoTimestamps = 2,          // v2 timestamps removed
    CompressionEncryption = 3, // v3 compression and encryption support
    IndexEncryption = 4,       // v4 index encryption support
    RelativeChunkOffsets = 5,  // v5 offsets are relative to header
    DeleteRecords = 6,         // v6 record deletion support
    EncryptionKeyGuid = 7,     // v7 include key GUID
    FNameBasedCompression = 8, // v8 compression names included
    FrozenIndex = 9,           // v9 frozen index byte included
    PathHashIndex = 10,        // v10
    Fnv64BugFix = 11,          // v11
}

impl VersionMajor {
    pub(crate) fn iterator() -> Iter<'static, Self> {
        use VersionMajor::*;
        static VERSIONS: [VersionMajor; 11] = [
            Initial,
            NoTimestamps,
            CompressionEncryption,
            IndexEncryption,
            RelativeChunkOffsets,
            DeleteRecords,
            EncryptionKeyGuid,
            FNameBasedCompression,
            FrozenIndex,
            PathHashIndex,
            Fnv64BugFix,
        ];
        VERSIONS.iter()
    }
}

impl VersionMajor {
    pub(crate) fn footer_size(&self) -> u64 {
        // (magic + version): u32 + (offset + size): u64 + hash: [u8; 20]
        let mut size = 4 + 4 + 8 + 8 + 20;
        if *self >= VersionMajor::EncryptionKeyGuid {
            // encryption uuid: u128
            size += 16;
        }
        if *self >= VersionMajor::IndexEncryption {
            // encrypted: bool
            size += 1;
        }
        if *self == VersionMajor::FrozenIndex {
            // frozen index: bool
            size += 1;
        }
        // FIXME: this does not handle the distinction between v8a and v8b. v8a has 32 * 4 bytes
        // while v8b has 32 * 5 bytes.
        if *self >= VersionMajor::FNameBasedCompression {
            // additional compression name
            size += 32 * 5;
        }
        size
    }
}
