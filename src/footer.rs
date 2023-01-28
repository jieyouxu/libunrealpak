use crate::errors::UnrealpakError;
use crate::ext::{ReadExt, WriteExt};
use crate::hash::Hash;
use crate::version::VersionMajor;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use core::panic;
use std::io::{Read, Write};

#[derive(Debug)]
pub(crate) struct Footer {
    /// Present on versions >= 7.
    pub(crate) encryption_key_guid: Option<u128>,
    /// Present on versions >= 4.
    pub(crate) is_index_encrypted: Option<bool>,
    /// Must be `0x5A6F12E1`.
    pub(crate) magic: u32,
    pub(crate) version: VersionMajor,
    pub(crate) index_offset: u64,
    pub(crate) index_size: u64,
    pub(crate) index_hash: Hash,
    /// Present on version 9 only.
    pub(crate) is_index_frozen: Option<bool>,
    /// Present on version 8 (128 bytes) or version >8 (160 bytes).
    pub(crate) compression_methods: Option<Vec<u8>>,
}

impl Footer {
    pub(crate) fn size(&self) -> u32 {
        let mut size = 0;
        size += if self.encryption_key_guid.is_some() {
            16
        } else {
            0
        };
        size += if self.is_index_encrypted.is_some() {
            1
        } else {
            0
        };
        size += 4; // magic
        size += 4; // version
        size += 8; // index offset
        size += 8; // index size
        size += 20; // index hash
        size += if self.is_index_frozen.is_some() { 1 } else { 0 };
        size += if self.compression_methods.is_some() {
            match self.version {
                VersionMajor::FNameBasedCompression => 128,
                v if v > VersionMajor::FNameBasedCompression => 160,
                _ => panic!("unexpected compression method size"),
            }
        } else {
            0
        };
        size
    }
}

pub(crate) fn read_footer<R: Read>(
    reader: &mut R,
    version_hint: VersionMajor,
) -> Result<Footer, UnrealpakError> {
    let encryption_key_guid = if version_hint >= VersionMajor::EncryptionKeyGuid {
        Some(reader.read_u128::<LE>()?)
    } else {
        None
    };

    let is_index_encrypted = if version_hint >= VersionMajor::IndexEncryption {
        Some(reader.read_bool()?)
    } else {
        None
    };

    let magic = reader.read_u32::<LE>()?;
    if magic != crate::MAGIC {
        return Err(UnrealpakError::ValidationError("magic"));
    }

    let version = reader.read_u32::<LE>()?;
    let version = match version {
        1 => VersionMajor::Initial,
        2 => VersionMajor::NoTimestamps,
        3 => VersionMajor::CompressionEncryption,
        4 => VersionMajor::IndexEncryption,
        5 => VersionMajor::RelativeChunkOffsets,
        6 => VersionMajor::DeleteRecords,
        7 => VersionMajor::EncryptionKeyGuid,
        8 => VersionMajor::FNameBasedCompression,
        9 => VersionMajor::FrozenIndex,
        10 => VersionMajor::PathHashIndex,
        11 => VersionMajor::Fnv64BugFix,
        v => return Err(UnrealpakError::UnknownVersion(v)),
    };

    if version != version_hint {
        return Err(UnrealpakError::VersionMismatch {
            expected: version_hint as u32,
            actual: version as u32,
        });
    }

    let index_offset = reader.read_u64::<LE>()?;
    let index_size = reader.read_u64::<LE>()?;
    let index_hash = Hash(reader.read_hash()?);

    let is_index_frozen = if version_hint == VersionMajor::FrozenIndex {
        Some(reader.read_bool()?)
    } else {
        None
    };

    let compression_methods = match version_hint {
        VersionMajor::FNameBasedCompression => {
            let mut cm = [0u8; 128];
            reader.read_exact(&mut cm)?;
            Some(cm.to_vec())
        }
        v if v > VersionMajor::FNameBasedCompression => {
            let mut cm = [0u8; 160];
            reader.read_exact(&mut cm)?;
            Some(cm.to_vec())
        }
        _ => None,
    };

    Ok(Footer {
        encryption_key_guid,
        is_index_encrypted,
        magic,
        version,
        index_offset,
        index_size,
        index_hash,
        is_index_frozen,
        compression_methods,
    })
}

pub(crate) fn write_footer<W: Write>(
    writer: &mut W,
    footer: &Footer,
) -> Result<(), UnrealpakError> {
    if footer.version >= VersionMajor::EncryptionKeyGuid {
        writer.write_u128::<LE>(footer.encryption_key_guid.unwrap())?;
    }

    if footer.version >= VersionMajor::IndexEncryption {
        writer.write_bool(footer.is_index_encrypted.unwrap())?;
    };

    writer.write_u32::<LE>(footer.magic)?;
    writer.write_u32::<LE>(footer.version as u32)?;
    writer.write_u64::<LE>(footer.index_offset)?;
    writer.write_u64::<LE>(footer.index_size)?;
    writer.write_all(&footer.index_hash.0)?;

    if footer.version == VersionMajor::FrozenIndex {
        writer.write_bool(footer.is_index_frozen.unwrap())?;
    }

    if footer.version >= VersionMajor::FNameBasedCompression {
        writer.write_all(&footer.compression_methods.as_ref().unwrap()[..])?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_footer_pack_v11() {
        let v11_footer = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xE1, 0x12, 0x6F, 0x5A, 0x0B, 0x00, 0x00, 0x00, 0xF7, 0x34, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34,
            0x72, 0xD7, 0xAA, 0x90, 0x47, 0xD4, 0xC8, 0x05, 0x3F, 0x9B, 0x42, 0x48, 0x13, 0x25,
            0xC3, 0x88, 0x09, 0x8F, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(v11_footer.len(), 221);

        let mut reader = Cursor::new(v11_footer);
        let footer = read_footer(&mut reader, VersionMajor::Fnv64BugFix).unwrap();
        assert_eq!(footer.size(), 221);

        assert_eq!(footer.encryption_key_guid, Some(0));
        assert_eq!(footer.is_index_encrypted, Some(false));
        assert_eq!(footer.magic, 0x5A6F12E1);
        assert_eq!(footer.version, VersionMajor::Fnv64BugFix);
        assert_eq!(footer.index_offset, 0x34F7);
        assert_eq!(footer.index_size, 0xAD);
        assert_eq!(
            footer.index_hash,
            Hash([
                0x34, 0x72, 0xD7, 0xAA, 0x90, 0x47, 0xD4, 0xC8, 0x05, 0x3F, 0x9B, 0x42, 0x48, 0x13,
                0x25, 0xC3, 0x88, 0x09, 0x8F, 0x07,
            ])
        );
        assert_eq!(footer.is_index_frozen, None);
        assert_eq!(footer.compression_methods.unwrap().len(), 160);
    }

    #[test]
    fn test_write_footer_pack_v11() {
        let v11_footer = Footer {
            encryption_key_guid: Some(0),
            is_index_encrypted: Some(false),
            magic: crate::MAGIC,
            version: VersionMajor::Fnv64BugFix,
            index_offset: 0x34F7,
            index_size: 0xAD,
            index_hash: Hash([
                0x34, 0x72, 0xD7, 0xAA, 0x90, 0x47, 0xD4, 0xC8, 0x05, 0x3F, 0x9B, 0x42, 0x48, 0x13,
                0x25, 0xC3, 0x88, 0x09, 0x8F, 0x07,
            ]),
            is_index_frozen: None,
            compression_methods: Some(vec![0u8; 160]),
        };

        let mut buf = vec![];
        let mut writer = Cursor::new(&mut buf);
        write_footer(&mut writer, &v11_footer).unwrap();

        assert_eq!(buf.len() as u32, v11_footer.size());
        assert_eq!(
            buf,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xE1, 0x12, 0x6F, 0x5A, 0x0B, 0x00, 0x00, 0x00, 0xF7, 0x34, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0xAD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x34,
                0x72, 0xD7, 0xAA, 0x90, 0x47, 0xD4, 0xC8, 0x05, 0x3F, 0x9B, 0x42, 0x48, 0x13, 0x25,
                0xC3, 0x88, 0x09, 0x8F, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ]
        );
    }
}
