use crate::decrypt::decrypt;
use crate::errors::UnrealpakError;
use crate::ext::{ReadExt, WriteExt};
use crate::full_directory_index::{
    read_full_directory_index, write_full_directory_index, FullDirectoryIndex,
};
use crate::path_hash_index::{read_path_hash_index, write_path_hash_index, PathHashIndex};
use crate::record::{read_record, write_record, Record};
use crate::version::VersionMajor;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use sha1::{Digest, Sha1};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

#[derive(Debug, PartialEq)]
pub(crate) struct Index {
    pub(crate) mount_point: String,
    pub(crate) record_count: u32,
    pub(crate) path_hash_seed: Option<u64>,
    pub(crate) path_hash_index: Option<PathHashIndex>,
    pub(crate) full_directory_index: Option<FullDirectoryIndex>,
    pub(crate) records: Vec<Record>,
}

impl Index {
    pub(crate) const ENCODED_INDEX_RECORD_SIZE: u64 = 0xC;

    pub(crate) fn serialized_size(&self, version: VersionMajor) -> u64 {
        if version >= VersionMajor::PathHashIndex {
            4 // mount point size
            + self.mount_point.len() as u64 + 1 // mount point with terminating byte
            + 4 // entry count
            + 8 // path hash seed
            + 4 // has path hash index
            + if self.path_hash_index.is_some() { 8 + 8 + 20 } else { 0 } // path hash index meta
            + 4 // has full directory index
            + if self.full_directory_index.is_some() { 8 + 8 + 20 } else { 0 }
            + 4 // encoded entry size
            + self.records.len() as u64 * Self::ENCODED_INDEX_RECORD_SIZE // encoded records
            + 4 // file count
        } else {
            todo!()
        }
    }
}

/// Reading an [`Index`] requires a reader to the full file stream because the offsets for
/// `PashHashIndex` and `FullDirectoryIndex` are *absolute* and not *relative*.
pub(crate) fn read_index<R: Read + Seek>(
    pak_reader: &mut R,
    index_offset: u64,
    index_size: u64,
    version: VersionMajor,
    is_index_encrypted: bool,
    key: Option<aes::Aes256Dec>,
) -> Result<Index, UnrealpakError> {
    pak_reader.seek(SeekFrom::Start(index_offset))?;
    let mut index_buf = pak_reader.read_len(index_size as usize)?;
    if is_index_encrypted {
        decrypt(&key, &mut index_buf)?;
    }
    let mut index_reader = Cursor::new(&mut index_buf);

    let mount_point = index_reader.read_cstring()?;
    let record_count = index_reader.read_u32::<LE>()?;
    let path_hash_seed = if version >= VersionMajor::PathHashIndex {
        Some(index_reader.read_u64::<LE>()?)
    } else {
        None
    };

    let path_hash_index = if version >= VersionMajor::PathHashIndex {
        let has_path_hash_index = match index_reader.read_u32::<LE>()? {
            0 => false,
            1 => true,
            v => return Err(UnrealpakError::Bool(v as u64)),
        };
        if has_path_hash_index {
            let path_hash_index_offset = index_reader.read_u64::<LE>()?;
            let path_hash_index_size = index_reader.read_u64::<LE>()?;
            // TODO: verify PHI hash.
            let _path_hash_index_hash = index_reader.read_hash()?;
            pak_reader.seek(SeekFrom::Start(path_hash_index_offset))?;
            let mut phi_buf = pak_reader.read_len(path_hash_index_size as usize)?;
            if is_index_encrypted {
                decrypt(&key, &mut phi_buf)?;
            }
            let mut phi_reader = Cursor::new(&mut phi_buf);
            let phi = read_path_hash_index(&mut phi_reader)?;
            Some(phi)
        } else {
            None
        }
    } else {
        None
    };

    let full_directory_index = if version >= VersionMajor::PathHashIndex {
        let has_full_directory_index = match index_reader.read_u32::<LE>()? {
            0 => false,
            1 => true,
            v => return Err(UnrealpakError::Bool(v as u64)),
        };
        if has_full_directory_index {
            let full_directory_index_offset = index_reader.read_u64::<LE>()?;
            let full_directory_index_size = index_reader.read_u64::<LE>()?;
            // TODO: verify FDI hash
            let _full_directory_index_hash = index_reader.read_hash()?;
            pak_reader.seek(SeekFrom::Start(full_directory_index_offset))?;
            let mut fdi_buf = pak_reader.read_len(full_directory_index_size as usize)?;
            if is_index_encrypted {
                decrypt(&key, &mut fdi_buf)?;
            }
            let mut fdi_buf_reader = Cursor::new(&mut fdi_buf);
            let fdi = read_full_directory_index(&mut fdi_buf_reader)?;
            Some(fdi)
        } else {
            None
        }
    } else {
        None
    };

    let _record_info_size = index_reader.read_u32::<LE>()?;
    let mut records = vec![];
    for _ in 0..record_count {
        records.push(read_record(&mut index_reader, version)?);
    }

    Ok(Index {
        mount_point,
        record_count,
        path_hash_seed,
        path_hash_index,
        full_directory_index,
        records,
    })
}

pub(crate) fn write_index<W: Write + Seek>(
    writer: &mut W,
    index: &Index,
    offset: u64,
    version: VersionMajor,
) -> Result<(), UnrealpakError> {
    // TODO: handle encryptindex
    writer.write_cstring(&index.mount_point)?;
    writer.write_u32::<LE>(index.record_count)?;

    if version < VersionMajor::PathHashIndex {
        // TODO: determine (version < 10)'s IndexRecord[N]
        todo!();
        return Ok(());
    }

    writer.write_u64::<LE>(index.path_hash_seed.unwrap())?;

    let mut phi_buf = vec![];
    if let Some(phi) = &index.path_hash_index {
        let mut phi_writer = Cursor::new(&mut phi_buf);
        write_path_hash_index(&mut phi_writer, phi)?;
    }

    let mut fdi_buf = vec![];
    if let Some(fdi) = &index.full_directory_index {
        let mut fdi_writer = Cursor::new(&mut fdi_buf);
        write_full_directory_index(&mut fdi_writer, fdi)?;
    }

    let records_size = if index.record_count > 0 {
        assert!(!index.records.is_empty());
        let mut size = 0;
        for r in &index.records {
            size += Index::ENCODED_INDEX_RECORD_SIZE;
        }
        size
    } else {
        0
    };

    dbg!(records_size);

    dbg!(index.serialized_size(version));
    let phi_offset = offset + index.serialized_size(version);
    let fdi_offset = phi_offset + phi_buf.len() as u64;
    eprintln!("phi_offset = 0x{:X?}", phi_offset);
    dbg!(phi_buf.len());
    eprintln!("fdi_offset = 0x{:X?}", fdi_offset);

    if let Some(phi) = &index.path_hash_index {
        writer.write_u32::<LE>(1)?;
        writer.write_u64::<LE>(phi_offset)?;
        writer.write_u64::<LE>(phi.serialized_size())?;
        let path_hash_index_hash = sha1_hash(&phi_buf[..]);
        writer.write_all(&path_hash_index_hash)?;
    }

    if let Some(fdi) = &index.full_directory_index {
        writer.write_u32::<LE>(1)?;
        writer.write_u64::<LE>(fdi_offset)?;
        writer.write_u64::<LE>(fdi.serialized_size())?;
        let full_directory_index_hash = sha1_hash(&fdi_buf[..]);
        writer.write_all(&full_directory_index_hash)?;
    }

    writer.write_u32::<LE>(records_size as u32)?;

    for rec in &index.records {
        write_record(writer, version, rec, crate::record::EntryLocation::Index)?;
    }
    writer.write_u32::<LE>(0)?; // file_count?

    writer.write_all(&phi_buf[..])?;
    writer.write_all(&fdi_buf[..])?;

    Ok(())
}

fn sha1_hash(data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::Compression;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    #[test]
    fn test_read_index_pack_v11() {
        let mut pack_v11 = include_bytes!("../tests/packs/pack_v11.pak");
        let mut pak_reader = Cursor::new(&mut pack_v11);
        let index = read_index(
            &mut pak_reader,
            0x34F7,
            0xAD,
            VersionMajor::Fnv64BugFix,
            false,
            None,
        )
        .unwrap();

        assert_eq!(index.mount_point, "../mount/point/root/".to_owned());
        assert_eq!(index.record_count, 4);
        assert_eq!(
            index.path_hash_seed,
            Some(u64::from_le_bytes([
                0x7D, 0x5A, 0x5C, 0x20, 0x00, 0x00, 0x00, 0x00
            ]))
        );

        let expected_phi = PathHashIndex(vec![
            (
                u64::from_le_bytes([0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]),
                0x00,
            ),
            (
                u64::from_le_bytes([0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20]),
                0x0C,
            ),
            (
                u64::from_le_bytes([0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50]),
                0x18,
            ),
            (
                u64::from_le_bytes([0xD0, 0x75, 0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32]),
                0x24,
            ),
        ]);

        assert_eq!(index.path_hash_index, Some(expected_phi));

        let expected_fdi = FullDirectoryIndex({
            let mut fdi = BTreeMap::new();
            fdi.insert("/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("test.png".to_owned(), 0xC);
                files.insert("test.txt".to_owned(), 0x18);
                files.insert("zeros.bin".to_owned(), 0x24);
                files
            });
            fdi.insert("directory/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("nested.txt".to_owned(), 0x0);
                files
            });
            fdi
        });

        assert_eq!(index.full_directory_index, Some(expected_fdi));

        let expected_records = vec![
            Record {
                offset: 0,
                uncompressed_size: 596,
                compression_method: Compression::None,
                compressed_size: 596,
                timestamp: None,
                blocks: None,
                is_encrypted: Some(false),
                compression_block_size: Some(0),
                hash: None,
            },
            Record {
                offset: 649,
                uncompressed_size: 10257,
                compression_method: Compression::None,
                compressed_size: 10257,
                timestamp: None,
                blocks: None,
                is_encrypted: Some(false),
                compression_block_size: Some(0),
                hash: None,
            },
            Record {
                offset: 10959,
                uncompressed_size: 446,
                compression_method: Compression::None,
                compressed_size: 446,
                timestamp: None,
                blocks: None,
                is_encrypted: Some(false),
                compression_block_size: Some(0),
                hash: None,
            },
            Record {
                offset: 11458,
                uncompressed_size: 2048,
                compression_method: Compression::None,
                compressed_size: 2048,
                timestamp: None,
                blocks: None,
                is_encrypted: Some(false),
                compression_block_size: Some(0),
                hash: None,
            },
        ];

        assert_eq!(index.records, expected_records);
    }

    #[test]
    fn test_write_index_pack_v11() {
        let index = Index {
            mount_point: "../mount/point/root/".to_owned(),
            record_count: 4,
            path_hash_seed: Some(u64::from_le_bytes([
                0x7D, 0x5A, 0x5C, 0x20, 0x00, 0x00, 0x00, 0x00,
            ])),
            path_hash_index: Some(PathHashIndex(vec![
                (
                    u64::from_le_bytes([0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]),
                    0x00,
                ),
                (
                    u64::from_le_bytes([0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20]),
                    0x0C,
                ),
                (
                    u64::from_le_bytes([0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50]),
                    0x18,
                ),
                (
                    u64::from_le_bytes([0xD0, 0x75, 0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32]),
                    0x24,
                ),
            ])),
            full_directory_index: Some(FullDirectoryIndex({
                let mut fdi = BTreeMap::new();
                fdi.insert("/".to_owned(), {
                    let mut files = BTreeMap::new();
                    files.insert("test.png".to_owned(), 0xC);
                    files.insert("test.txt".to_owned(), 0x18);
                    files.insert("zeros.bin".to_owned(), 0x24);
                    files
                });
                fdi.insert("directory/".to_owned(), {
                    let mut files = BTreeMap::new();
                    files.insert("nested.txt".to_owned(), 0x0);
                    files
                });
                fdi
            })),
            records: vec![
                Record {
                    offset: 0,
                    uncompressed_size: 596,
                    compression_method: Compression::None,
                    compressed_size: 596,
                    timestamp: None,
                    blocks: None,
                    is_encrypted: Some(false),
                    compression_block_size: Some(0),
                    hash: None,
                },
                Record {
                    offset: 649,
                    uncompressed_size: 10257,
                    compression_method: Compression::None,
                    compressed_size: 10257,
                    timestamp: None,
                    blocks: None,
                    is_encrypted: Some(false),
                    compression_block_size: Some(0),
                    hash: None,
                },
                Record {
                    offset: 10959,
                    uncompressed_size: 446,
                    compression_method: Compression::None,
                    compressed_size: 446,
                    timestamp: None,
                    blocks: None,
                    is_encrypted: Some(false),
                    compression_block_size: Some(0),
                    hash: None,
                },
                Record {
                    offset: 11458,
                    uncompressed_size: 2048,
                    compression_method: Compression::None,
                    compressed_size: 2048,
                    timestamp: None,
                    blocks: None,
                    is_encrypted: Some(false),
                    compression_block_size: Some(0),
                    hash: None,
                },
            ],
        };

        let expected_bytes = include_bytes!("../tests/packs/pack_v11.pak");
        let mut actual_bytes = vec![0u8; 173];
        let mut writer = Cursor::new(&mut actual_bytes);
        let index_offset = 0x34F7usize;
        let footer_offset = expected_bytes.len() - VersionMajor::Fnv64BugFix.footer_size() as usize;
        write_index(&mut writer, &index, 0x34F7, VersionMajor::Fnv64BugFix).unwrap();

        eprintln!("{:02X?}", &expected_bytes[index_offset..footer_offset]);
        eprintln!("{:02X?}", &actual_bytes[..]);

        assert_eq!(
            &expected_bytes[index_offset..footer_offset],
            &actual_bytes[..]
        )
    }
}
