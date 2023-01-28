use crate::errors::UnrealpakError;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io::{Read, Write};

#[derive(Debug, PartialEq)]
pub(crate) struct Block {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

pub(crate) fn read_block<R: Read>(reader: &mut R) -> Result<Block, UnrealpakError> {
    let start = reader.read_u64::<LE>()?;
    let end = reader.read_u64::<LE>()?;
    Ok(Block { start, end })
}

pub(crate) fn write_block<W: Write>(writer: &mut W, block: &Block) -> Result<(), UnrealpakError> {
    writer.write_u64::<LE>(block.start)?;
    writer.write_u64::<LE>(block.end)?;
    Ok(())
}
