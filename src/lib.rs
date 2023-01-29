mod block;
mod compression;
mod decrypt;
mod errors;
mod ext;
mod fnv64;
mod footer;
mod full_directory_index;
mod hash;
mod index;
mod pak;
mod pak_reader;
mod pak_writer;
mod path_hash_index;
mod record;
mod strcrc32;
mod version;

pub(crate) const MAGIC: u32 = 0x5A6F12E1;
