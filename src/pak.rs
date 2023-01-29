use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use aes::Aes256Dec;

use crate::decrypt::decrypt;
use crate::errors::UnrealpakError;
use crate::ext::ReadExt;
use crate::footer::read_footer;
use crate::index::{read_index, Index};
use crate::version::VersionMajor;

#[derive(Debug, PartialEq)]
pub struct Pak {
    pub(crate) version: VersionMajor,
    pub(crate) index: Index,
}
