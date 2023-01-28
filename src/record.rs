use crate::{Compression, Hash};

#[derive(Debug, PartialEq)]
pub(crate) struct Record {
    pub(crate) offset: u64,
    pub(crate) compressed_size: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) compression_method: Compression,
    pub(crate) timestamp: Option<u64>,
    pub(crate) hash: Hash,
    pub(crate) blocks: Option<Vec<Block>>,
    pub(crate) is_encrypted: Option<bool>,
    pub(crate) block_uncompressed_size: Option<u32>,
}

#[derive(Debug, PartialEq)]
pub(crate) struct Block {
    pub(crate) start: u64,
    pub(crate) end: u64,
}
