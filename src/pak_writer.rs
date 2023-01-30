use crate::block::Block;
use crate::compression::Compression;
use crate::errors::UnrealpakError;
use crate::fnv64::fnv64;
use crate::hash::Hash;
use crate::path_hash_index::PathHashIndex;
use crate::record::{write_record, Record};
use crate::strcrc32::strcrc32;
use crate::version::VersionMajor;
use aes::cipher::BlockSizeUser;
use aes::Aes256Enc;
use flate2::write::ZlibEncoder;
use log::{debug, info};
use sha1::{Digest, Sha1};
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::{fs, option};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub struct PakWriterOptions {
    pub compression_method: Compression,
    pub encrypt_data: Option<Aes256Enc>,
    pub encrypt_index: Option<Aes256Enc>,
}

pub fn write_pak<W, P, O>(
    writer: &mut W,
    version: VersionMajor,
    pack_root_path: P,
    output_pak_path: O,
    options: &PakWriterOptions,
) -> Result<(), UnrealpakError>
where
    W: Write + Seek,
    P: AsRef<Path>,
    O: AsRef<Path>,
{
    let pack_root_path = pack_root_path.as_ref();
    let output_pak_path = output_pak_path.as_ref();
    info!("output_pak_path {:?}", output_pak_path);
    let path_hash_seed = strcrc32(
        output_pak_path
            .to_str()
            .unwrap()
            .to_owned()
            .to_ascii_lowercase()
            .as_bytes(),
    );

    info!(
        "collecting directory tree snapshot with root directory {:?}",
        std::fs::canonicalize(pack_root_path)?
    );
    let files = {
        let mut files = vec![];
        for entry in WalkDir::new(pack_root_path)
            .sort_by_file_name()
            .into_iter()
            .filter_map(|entry| entry.ok())
        {
            if let Ok(metadata) = entry.metadata() {
                if metadata.is_file() {
                    if let Ok(p) = entry.path().strip_prefix(pack_root_path) {
                        if let Some(s) = p.to_str() {
                            files.push(s.to_owned());
                        }
                    }
                }
            }
        }
        files
    };
    info!("collected files {:#?}", &files);

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
    let mut data_record_headers = Vec::with_capacity(files.len());
    let mut file_hashes = Vec::with_capacity(files.len());
    for file in &files {
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
            encrypt(key, &mut file_content);
        }

        let mut hasher = Sha1::new();
        hasher.update(&file_content[..]);
        let file_hash = Hash(hasher.finalize().into());
        file_hashes.push(file_hash.clone());

        const DATA_RECORD_HEADER_SIZE: u64 = {
            8 // u64 offset
            + 8 // u64 size
            + 8 // uncompressed size
            + 4 // compression method
            + 20 // record hash
            + 5 // u8 zeros[5]
        };

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
        data_record_headers.push(record);
        writer.write_all(&mut file_content)?;
        offset = writer.stream_position()?;
    }
    assert_eq!(files.len(), data_record_headers.len());
    assert_eq!(file_hashes.len(), data_record_headers.len());

    let mut path_hashes = vec![];
    for file in &files {
        path_hashes.push(fnv64(file.as_bytes(), path_hash_seed as u64));
    }
    assert_eq!(path_hashes.len(), data_record_headers.len());

    let mut encoded_entry_offsets = Vec::with_capacity(files.len());
    for i in 0..files.len() {
        encoded_entry_offsets.push(0xCu32 * i as u32);
    }

    // FIXME: what the fuck is a PashHashIndex? Apparently the offset is the index
    // into *encoded* IndexRecords... coming *before* PathHashIndex and FullDirectoryIndex...
    let path_hash_index = PathHashIndex(
        path_hashes
            .into_iter()
            .zip(encoded_entry_offsets.into_iter())
            .collect(),
    );

    debug!("path_hash_index = {:#X?}", &path_hash_index);

    todo!()
}

#[track_caller]
fn zero_pad(v: &mut Vec<u8>, alignment: usize) {
    assert!(alignment >= 1);
    if v.len() % alignment != 0 {
        v.extend(std::iter::repeat(0).take(((v.len() + alignment - 1) / alignment) * alignment))
    }
    assert!(v.len() % alignment == 0);
}

fn encrypt(key: &aes::Aes256Enc, bytes: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    for chunk in bytes.chunks_mut(16) {
        key.encrypt_block(aes::Block::from_mut_slice(chunk))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compression::Compression;
    use std::io::Cursor;

    fn init_logger() {
        let _ = env_logger::builder().is_test(true).try_init();
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
            output_pak_path,
            &super::PakWriterOptions {
                compression_method: Compression::None,
                encrypt_data: None,
                encrypt_index: None,
            },
        )
        .unwrap();

        let v11_pak = include_bytes!("../tests/packs/pack_v11.pak");

        assert_eq!(out_bytes.len(), v11_pak.len());
        assert_eq!(&out_bytes[..], &v11_pak[..]);
    }
}
