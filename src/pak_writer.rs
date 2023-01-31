use crate::block::Block;
use crate::compression::Compression;
use crate::errors::UnrealpakError;
use crate::fnv64::fnv64;
use crate::footer::{write_footer, Footer};
use crate::full_directory_index::FullDirectoryIndex;
use crate::hash::Hash;
use crate::index::{write_index, Index};
use crate::path_hash_index::PathHashIndex;
use crate::record::{write_record, Record};
use crate::strcrc32::strcrc32;
use crate::version::VersionMajor;
use crate::MAGIC;
use aes::cipher::{BlockSizeUser, KeyInit};
use aes::Aes256Enc;
#[cfg(windows)]
use byteorder::{ByteOrder, LittleEndian};
use flate2::write::ZlibEncoder;
use log::{debug, info};
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::io::{Seek, Write};
use std::path::Path;
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct PakWriterOptions {
    pub compression_method: Compression,
    pub encrypt_data: Option<u128>,
    pub encrypt_index: Option<u128>,
}

const ENCODED_RECORD_SIZE: u32 = {
    4 // u32 flags
    + 4 // u32 offset
    + 4 // u32 uncompressed size
};

const DATA_RECORD_HEADER_SIZE: u64 = {
    8 // u64 offset
    + 8 // u64 size
    + 8 // uncompressed size
    + 4 // compression method
    + 20 // record hash
    + 5 // u8 zeros[5]
};

pub fn write_pak<W, P, M, O>(
    writer: &mut W,
    version: VersionMajor,
    pack_root_path: P,
    mount_point: M,
    output_pak_path: O,
    options: &PakWriterOptions,
) -> Result<(), UnrealpakError>
where
    W: Write + Seek,
    P: AsRef<Path>,
    M: AsRef<Path>,
    O: AsRef<Path>,
{
    let pack_root_path = pack_root_path.as_ref();

    let mount_point = mount_point.as_ref();

    let output_pak_path = output_pak_path.as_ref();
    info!("output_pak_path {:?}", output_pak_path);
    let path_hash_seed = strcrc32(&utf16le_path_to_bytes(output_pak_path)?);

    info!(
        "collecting directory tree snapshot with root directory {:?}",
        std::fs::canonicalize(pack_root_path)?
    );
    let mut file_paths_utf16le = vec![];
    let mut file_paths = vec![];
    let mut full_directory_index = BTreeMap::new();
    let mut encoded_record_offset = 0;
    for entry in WalkDir::new(pack_root_path)
        .sort_by_file_name()
        .into_iter()
        .filter_map(|entry| entry.ok())
    {
        if let Ok(metadata) = entry.metadata() {
            if metadata.is_file() {
                if let Ok(p) = entry.path().strip_prefix(pack_root_path) {
                    file_paths.push(p.to_owned());

                    let utf8_path = p
                        .to_path_buf()
                        .into_os_string()
                        .into_string()
                        .map_err(UnrealpakError::OsString)?;

                    let (dirname, filename) = {
                        // Need to +1 so the path on the left has the slash.
                        let i = utf8_path.rfind("/").map(|i| i + 1);
                        match i {
                            Some(i) => {
                                let (l, r) = utf8_path.split_at(i);
                                (l.to_owned(), r.to_owned())
                            }
                            None => ("/".to_owned(), utf8_path),
                        }
                    };

                    full_directory_index
                        .entry(dirname)
                        .and_modify(|d: &mut BTreeMap<String, u32>| {
                            d.insert(filename.clone(), encoded_record_offset);
                        })
                        .or_insert_with(|| {
                            let mut files_and_offsets = BTreeMap::new();
                            files_and_offsets.insert(filename.clone(), encoded_record_offset);
                            files_and_offsets
                        });

                    // TODO: convert paths from UTF-8 to UTF-16LE *even on* Unix systems.
                    #[cfg(unix)]
                    {
                        file_paths_utf16le.push(convert_unix_path_to_utf16le_bytes(p));
                    }

                    #[cfg(windows)]
                    {
                        file_paths_utf16le.push(utf16le_path_to_bytes(p));
                    }

                    #[cfg(not(any(unix, windows)))]
                    unimplemented!("unsupported platform");

                    encoded_record_offset += ENCODED_RECORD_SIZE;
                }
            }
        }
    }
    info!("collected files {:#?}", &file_paths);

    // For each file (as data record)
    //  - Construct data record header
    //  - Write header
    //  - Write file contents
    // Construct index
    //  - Construct path hash index
    //  - Construct full directory index
    //  - Construct index records
    //  - Write index
    // Construct footer
    //  - Write footer

    let mut offset = 0u64;
    let mut records = Vec::with_capacity(file_paths.len());
    let mut file_hashes = Vec::with_capacity(file_paths.len());
    for file in &file_paths {
        let mut file_content = fs::read(pack_root_path.join(file))?;
        let uncompressed_size = file_content.len() as u64;
        let compressed_size = match options.compression_method {
            Compression::None => uncompressed_size,
            Compression::Zlib => {
                let mut z = ZlibEncoder::new(Vec::new(), flate2::Compression::default());
                z.write_all(&file_content[..])?;
                file_content = z.finish()?;
                file_content.len() as u64
            }
            Compression::Gzip | Compression::Oodle => todo!(),
        };

        if let Some(key) = &options.encrypt_data {
            zero_pad(&mut file_content, Aes256Enc::block_size());
            encrypt(*key, &mut file_content);
        }

        let mut hasher = Sha1::new();
        hasher.update(&file_content[..]);
        let file_hash = Hash(hasher.finalize().into());
        file_hashes.push(file_hash.clone());

        let data_start_offset = offset + DATA_RECORD_HEADER_SIZE;

        let record = Record {
            offset,
            uncompressed_size,
            compression_method: options.compression_method,
            compressed_size,
            timestamp: None,
            hash: Some(file_hash.clone()),
            blocks: Some(vec![Block {
                start: data_start_offset,
                end: data_start_offset + file_content.len() as u64,
            }]),
            is_encrypted: Some(options.encrypt_data.is_some()),
            compression_block_size: None,
        };

        write_record(writer, version, &record, crate::record::EntryLocation::Data)?;
        records.push(record);
        writer.write_all(&mut file_content)?;
        offset = writer.stream_position()?;
    }
    assert_eq!(file_paths.len(), records.len());
    assert_eq!(file_hashes.len(), records.len());

    let path_hash_index = {
        let path_hashes = {
            let mut path_hashes = vec![];
            for utf16le_path in &file_paths_utf16le {
                path_hashes.push(fnv64(utf16le_path, path_hash_seed as u64));
            }
            assert_eq!(path_hashes.len(), records.len());
            path_hashes
        };

        let mut path_hash_index = vec![];
        for i in 0..path_hashes.len() {
            path_hash_index.push((path_hashes[i], ENCODED_RECORD_SIZE * i as u32));
        }
        PathHashIndex(path_hash_index)
    };

    debug!("path_hash_index = {:#X?}", &path_hash_index);

    let full_directory_index = FullDirectoryIndex(full_directory_index);

    debug!("full_directory_index = {:#X?}", &full_directory_index);

    let mount_point = mount_point
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(UnrealpakError::OsString)?;

    let index = Index {
        mount_point,
        record_count: file_paths.len() as u32,
        path_hash_seed: Some(path_hash_seed as u64),
        path_hash_index: Some(path_hash_index),
        full_directory_index: Some(full_directory_index),
        records,
    };

    let mut index_buf = vec![];
    let mut index_buf_writer = Cursor::new(&mut index_buf);
    write_index(
        &mut index_buf_writer,
        &index,
        writer.stream_position()?,
        version,
    )?;

    let index_offset = writer.stream_position()?;
    let index_size = index.serialized_size(version);
    dbg!(index_buf.len());
    let index_hash = {
        let mut hasher = Sha1::new();
        dbg!(&index_buf[..index_size as usize].len());
        hasher.update(&index_buf[..index_size as usize]);
        Hash(hasher.finalize().into())
    };

    debug!("index_hash = {:0x?}", index_hash);

    writer.write_all(&index_buf)?;

    let footer = Footer {
        encryption_key_guid: Some(options.encrypt_data.unwrap_or(0)),
        is_index_encrypted: Some(false),
        magic: MAGIC,
        version,
        index_offset,
        index_size,
        index_hash,
        is_index_frozen: None,
        // TODO: implement compression
        compression_methods: Some(vec![0u8; 160]),
    };

    write_footer(writer, &footer)?;

    Ok(())
}

#[cfg(unix)]
fn convert_unix_path_to_utf16le_bytes<P: AsRef<Path>>(path: P) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_ref()
        .as_os_str()
        .as_bytes()
        .iter()
        .flat_map(|&b| [b, 0])
        .collect()
}

#[cfg(unix)]
fn utf16le_path_to_bytes<P: AsRef<Path>>(path: P) -> Result<Vec<u8>, UnrealpakError> {
    Ok(path
        .as_ref()
        .to_path_buf()
        .into_os_string()
        .into_string()
        .map_err(UnrealpakError::OsString)?
        .as_bytes()
        .to_owned())
}

#[cfg(windows)]
fn utf16le_path_to_bytes<P: AsRef<Path>>(path: P) -> Vec<u8> {
    use std::os::windows::ffi::OsStrExt;
    let path: Vec<u16> = path.as_ref().as_os_str().encode_wide();
    let mut buf = Vec::with_capacity(path.len() / 2);
    LittleEndian::write_u16_into(&path, &mut buf);
    buf
}

#[cfg(not(any(unix, windows)))]
fn utf16le_path_to_bytes<P: AsRef<Path>>(path: P) -> Vec<u8> {
    unimplemented!("unsupported platform")
}

#[track_caller]
fn zero_pad(v: &mut Vec<u8>, alignment: usize) {
    assert!(alignment >= 1);
    if v.len() % alignment != 0 {
        v.extend(std::iter::repeat(0).take(((v.len() + alignment - 1) / alignment) * alignment))
    }
    assert!(v.len() % alignment == 0);
}

fn encrypt(key: u128, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    let key = Aes256Enc::new_from_slice(&key.to_le_bytes()).unwrap();
    for chunk in bytes.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::Compression;
    use std::io::{Cursor, Write};

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
    }

    #[test]
    fn try_index_hash() {
        let index: [u8; 0xAD] = [
            0x15, 0x00, 0x00, 0x00, 0x2E, 0x2E, 0x2F, 0x6D, 0x6F, 0x75, 0x6E, 0x74, 0x2F, 0x70,
            0x6F, 0x69, 0x6E, 0x74, 0x2F, 0x72, 0x6F, 0x6F, 0x74, 0x2F, 0x00, 0x04, 0x00, 0x00,
            0x00, 0x7D, 0x5A, 0x5C, 0x20, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xA4,
            0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x66, 0x8E, 0x2D, 0xAF, 0x1C, 0x70, 0xB4, 0xC3, 0x62, 0x9F, 0x59, 0xCA, 0x98,
            0xF5, 0xEA, 0x3E, 0xA5, 0x56, 0xEC, 0xA7, 0x01, 0x00, 0x00, 0x00, 0xDC, 0x35, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x70,
            0x79, 0xEA, 0xE0, 0x7F, 0x19, 0xA2, 0x51, 0xA1, 0x4E, 0xFD, 0xE5, 0xA4, 0x8D, 0x7D,
            0x22, 0x7E, 0xD5, 0xAE, 0x73, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00,
            0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x89, 0x02, 0x00,
            0x00, 0x11, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xCF, 0x2A, 0x00, 0x00, 0xBE,
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0xC2, 0x2C, 0x00, 0x00, 0x00, 0x08, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let guess_hash: [u8; 20] = {
            let mut hasher = Sha1::new();
            hasher.update(&index[..]);
            hasher.finalize().into()
        };

        let expected_hash: [u8; 0x14] = [
            0x34, 0x72, 0xD7, 0xAA, 0x90, 0x47, 0xD4, 0xC8, 0x05, 0x3F, 0x9B, 0x42, 0x48, 0x13,
            0x25, 0xC3, 0x88, 0x09, 0x8F, 0x07,
        ];

        assert_eq!(guess_hash, expected_hash);
    }

    #[test]
    fn test_write_pak_v11() {
        init_logger();

        let mut out_bytes = vec![];
        let mut writer = Cursor::new(&mut out_bytes);
        let pack_root_path = "./tests/pack/root";
        let output_pak_path =
            "/home/truman/projects/drg-modding/tools/unpak/tests/packs/pack_v11.pak";
        write_pak(
            &mut writer,
            VersionMajor::Fnv64BugFix,
            pack_root_path,
            "../mount/point/root/",
            output_pak_path,
            &super::PakWriterOptions {
                compression_method: Compression::None,
                encrypt_data: None,
                encrypt_index: None,
            },
        )
        .unwrap();

        let v11_pak = include_bytes!("../tests/packs/pack_v11.pak");

        fs::write("./target/test_v11.pak", &out_bytes).unwrap();

        assert_eq!(out_bytes.len(), v11_pak.len());
        assert_eq!(&out_bytes[..], &v11_pak[..]);
    }
}
