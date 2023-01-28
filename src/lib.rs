mod compression;
mod errors;
mod ext;
mod fnv64;
mod footer;
mod full_directory_index;
mod hash;
mod index;
mod path_hash_index;
mod record;
mod version;
mod block;

pub(crate) const MAGIC: u32 = 0x5A6F12E1;
