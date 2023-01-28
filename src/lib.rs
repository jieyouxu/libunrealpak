mod errors;
mod footer;
mod hash;
mod version;
mod ext;
mod index;
mod record;
mod compression;
mod path_hash_index;
mod full_directory_index;

use errors::*;
use hash::*;
use version::*;
use index::*;
use record::*;
use compression::*;
use path_hash_index::*;
use full_directory_index::*;
use ext::*;

pub(crate) const MAGIC: u32 = 0x5A6F12E1;
