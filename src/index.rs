use crate::{Compression, Hash, PathHashIndex, FullDirectoryIndex, Record};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
pub(crate) struct LegacyIndex {
    pub(crate) mount_point: String,
    pub(crate) entries: Vec<Record>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct NewIndex {
    pub(crate) mount_point: String,
    pub(crate) entry_count: u32,
    pub(crate) path_hash_seed: u64,
    pub(crate) path_hash_index: Option<PathHashIndex>,
    pub(crate) full_directory_index: Option<FullDirectoryIndex>,
    pub(crate) entries: BTreeMap<String, Record>,
}
