use crate::{PathHashIndex, FullDirectoryIndex, Record};
use std::collections::BTreeMap;

#[derive(Debug, PartialEq)]
pub(crate) struct Index {
    pub(crate) mount_point: String,
    pub(crate) record_count: u32,
    pub(crate) path_hash_seed: Option<u64>,
    pub(crate) path_hash_index: Option<PathHashIndex>,
    pub(crate) full_directory_index: Option<FullDirectoryIndex>,
    pub(crate) records: BTreeMap<String, Record>,
}
