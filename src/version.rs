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
