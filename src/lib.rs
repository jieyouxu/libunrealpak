mod errors;
mod footer;
mod hash;
mod version;
mod ext;

use errors::*;
use hash::*;
use version::*;

pub(crate) const MAGIC: u32 = 0x5A6F12E1;
