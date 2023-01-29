use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use aes::Aes256Enc;
use sha1::{Digest, Sha1};

use crate::compression::Compression;
use crate::errors::UnrealpakError;
use crate::hash::Hash;
use crate::record::{write_record, EntryLocation, Record};
use crate::version::VersionMajor;

pub fn write_pak<W: Write, F: AsRef<Path>, P: AsRef<Path>>(
    writer: &mut W,
    version: VersionMajor,
    files: Vec<F>,
    pak_path: P,
    compression: Compression,
    key: Option<Aes256Enc>,
) -> Result<(), UnrealpakError> {
    // TODO: implement encryption, encryptindex, compression
    let mut record_offsets = Vec::with_capacity(files.len());
    record_offsets[0] = 0;
    for i in 0..files.len() {
        if i == 

        // TODO: implement encryption and compression
        let file = File::open(&files[i])?;
        let mut file_reader = BufReader::new(file);
        let mut file_content = vec![];
        file_reader.read_to_end(&mut file_content)?;
        let mut hasher = Sha1::new();
        hasher.update(&file_content[..]);
        let file_hash = Hash(hasher.finalize().into());

        write_record(
            writer,
            version,
            &Record {
                offset: if i == 0 { 0 } else { record_offsets[i - 1] },
                uncompressed_size: file_content.len() as u64,
                compression_method: Compression::None,
                compressed_size: file_content.len() as u64,
                timestamp: None,
                hash: Some(file_hash),
                blocks: vec![],
                is_encrypted: todo!(),
                compression_block_size: todo!(),
            },
            EntryLocation::Data,
        )?;

        writer.write_all()
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::compression::Compression;
    use crate::full_directory_index::FullDirectoryIndex;
    use crate::index::Index;
    use crate::pak::Pak;
    use crate::path_hash_index::PathHashIndex;
    use crate::record::Record;
    use crate::strcrc32::strcrc32;
    use crate::version::VersionMajor;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use super::write_pak;

    #[test]
    fn test_write_pak_pack_v11() {
        let full_path = "/home/truman/projects/drg-modding/tools/unpak/tests/packs";
        // let v11_pack = Pak {
        //     version: VersionMajor::Fnv64BugFix,
        //     index: Index {
        //         mount_point: "../mount/point/root/".to_owned(),
        //         record_count: 4,
        //         path_hash_seed: Some(strcrc32(full_path).into()),
        //         path_hash_index: Some(PathHashIndex(vec![
        //             (
        //                 u64::from_le_bytes([0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]),
        //                 0x00,
        //             ),
        //             (
        //                 u64::from_le_bytes([0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20]),
        //                 0x0C,
        //             ),
        //             (
        //                 u64::from_le_bytes([0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50]),
        //                 0x18,
        //             ),
        //             (
        //                 u64::from_le_bytes([0xD0, 0x75, 0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32]),
        //                 0x24,
        //             ),
        //         ])),
        //         full_directory_index: Some(FullDirectoryIndex({
        //             let mut fdi = BTreeMap::new();
        //             fdi.insert("/".to_owned(), {
        //                 let mut files = BTreeMap::new();
        //                 files.insert("test.png".to_owned(), 0xC);
        //                 files.insert("test.txt".to_owned(), 0x18);
        //                 files.insert("zeros.bin".to_owned(), 0x24);
        //                 files
        //             });
        //             fdi.insert("directory/".to_owned(), {
        //                 let mut files = BTreeMap::new();
        //                 files.insert("nested.txt".to_owned(), 0x0);
        //                 files
        //             });
        //             fdi
        //         })),
        //         records: vec![
        //             Record {
        //                 offset: 0,
        //                 uncompressed_size: 596,
        //                 compression_method: Compression::None,
        //                 compressed_size: 596,
        //                 timestamp: None,
        //                 blocks: None,
        //                 is_encrypted: Some(false),
        //                 compression_block_size: Some(0),
        //                 hash: None,
        //             },
        //             Record {
        //                 offset: 649,
        //                 uncompressed_size: 10257,
        //                 compression_method: Compression::None,
        //                 compressed_size: 10257,
        //                 timestamp: None,
        //                 blocks: None,
        //                 is_encrypted: Some(false),
        //                 compression_block_size: Some(0),
        //                 hash: None,
        //             },
        //             Record {
        //                 offset: 10959,
        //                 uncompressed_size: 446,
        //                 compression_method: Compression::None,
        //                 compressed_size: 446,
        //                 timestamp: None,
        //                 blocks: None,
        //                 is_encrypted: Some(false),
        //                 compression_block_size: Some(0),
        //                 hash: None,
        //             },
        //             Record {
        //                 offset: 11458,
        //                 uncompressed_size: 2048,
        //                 compression_method: Compression::None,
        //                 compressed_size: 2048,
        //                 timestamp: None,
        //                 blocks: None,
        //                 is_encrypted: Some(false),
        //                 compression_block_size: Some(0),
        //                 hash: None,
        //             },
        //         ],
        //     },
        // };

        let reference_bytes = include_bytes!("../tests/packs/pack_v11.pak");
        let mut our_bytes = vec![];
        let mut our_writer = Cursor::new(&mut our_bytes);
        write_pak(
            &mut our_writer,
            VersionMajor::Fnv64BugFix,
            vec!["test.png", "test.txt", "zeros.bin", "directory/nested.txt"],
            full_path,
            Compression::None,
            None,
        )
        .unwrap();

        assert_eq!(reference_bytes.len(), our_bytes.len());
        assert_eq!(&reference_bytes[..], &our_bytes[..]);
    }
}
