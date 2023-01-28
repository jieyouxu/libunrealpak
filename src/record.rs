use crate::block::{write_block, Block};
use crate::compression::Compression;
use crate::errors::UnrealpakError;
use crate::ext::WriteExt;
use crate::hash::Hash;
use crate::version::VersionMajor;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use sha1::digest::typenum::Pow;
use std::io::{Read, Write};

#[derive(Debug, PartialEq)]
pub(crate) struct Record {
    pub(crate) offset: u64,
    pub(crate) uncompressed_size: u64,
    pub(crate) compression_method: Compression,
    pub(crate) compressed_size: u64,
    pub(crate) timestamp: Option<u64>,
    pub(crate) hash: Option<Hash>,
    pub(crate) blocks: Option<Vec<Block>>,
    pub(crate) is_encrypted: Option<bool>,
    pub(crate) compression_block_size: Option<u32>,
}

impl Record {
    pub(crate) fn serialized_size(
        &self,
        version: VersionMajor,
        compression_method: Compression,
    ) -> u64 {
        if version >= VersionMajor::PathHashIndex {
            let mut size = 4; // flags

            size += if self.offset > u32::MAX as u64 { 8 } else { 4 };
            size += if self.uncompressed_size > u32::MAX as u64 {
                8
            } else {
                4
            };
            if self.compression_method != Compression::None {
                size += if self.compressed_size > u32::MAX as u64 {
                    8
                } else {
                    4
                }
            }

            if let Some(blocks) = &self.blocks {
                if blocks.len() > 0 && (self.is_encrypted.unwrap_or_default() || blocks.len() == 1)
                {
                    for _ in blocks {
                        size += 4;
                    }
                }
            }

            size
        } else {
            let mut size = 0;
            size += 8; // offset
            size += 8; // compressed
            size += 8; // uncompressed
                       // FIXME: this does not handle v8a for now.
            size += match version != VersionMajor::FNameBasedCompression {
                true => 4,  // 32 bit compression
                false => 1, // 8 bit compression
            };
            size += match version == VersionMajor::Initial {
                true => 8, // timestamp
                false => 0,
            };
            size += 20; // hash
            size += match compression_method != Compression::None {
                true => 4 + (8 + 8) * self.blocks.as_ref().unwrap().len() as u64, // blocks
                false => 0,
            };
            size += 1; // encrypted
            size += match version >= VersionMajor::CompressionEncryption {
                true => 4, // blocks uncompressed
                false => 0,
            };
            size
        }
    }
}

fn serialized_size(
    version: VersionMajor,
    compression_method: Compression,
    offset: u64,
    uncompressed_size: u64,
    compressed_size: u64,
    block_count: u32,
    is_encrypted: bool,
) -> u64 {
    if version >= VersionMajor::PathHashIndex {
        let mut size = 4u64; // flags

        size += if offset > u32::MAX as u64 { 8 } else { 4 };
        size += if uncompressed_size > u32::MAX as u64 {
            8
        } else {
            4
        };
        if compression_method != Compression::None {
            size += if compressed_size > u32::MAX as u64 {
                8
            } else {
                4
            }
        }

        if block_count > 0 && (is_encrypted || block_count == 1) {
            size += 4 * block_count as u64;
        }

        size
    } else {
        let mut size = 0;
        size += 8; // offset
        size += 8; // compressed
        size += 8; // uncompressed
                   // FIXME: this does not handle v8a for now.
        size += match version != VersionMajor::FNameBasedCompression {
            true => 4,  // 32 bit compression
            false => 1, // 8 bit compression
        };
        size += match version == VersionMajor::Initial {
            true => 8, // timestamp
            false => 0,
        };
        size += 20; // hash
        size += match compression_method != Compression::None {
            true => 4 + (8 + 8) * block_count as u64, // blocks
            false => 0,
        };
        size += 1; // encrypted
        size += match version >= VersionMajor::CompressionEncryption {
            true => 4, // blocks uncompressed
            false => 0,
        };
        size
    }
}

pub(crate) fn read_record<R: Read>(
    reader: &mut R,
    version: VersionMajor,
) -> Result<Record, UnrealpakError> {
    if version >= VersionMajor::PathHashIndex {
        let bits = reader.read_u32::<LE>()?;
        let compression_method = match (bits >> 23) & 0x3f {
            0x01 | 0x10 | 0x20 => Compression::Zlib,
            _ => Compression::None,
        };

        let is_encrypted = (bits & (1 << 22)) != 0;
        let compression_block_count: u32 = (bits >> 6) & 0xffff;
        let mut block_uncompressed_size = bits & 0x3f;

        if block_uncompressed_size == 0x3f {
            block_uncompressed_size = reader.read_u32::<LE>()?;
        } else {
            block_uncompressed_size <<= 11;
        }

        let mut var_int = |bit: u32| -> Result<_, UnrealpakError> {
            Ok(if (bits & (1 << bit)) != 0 {
                reader.read_u32::<LE>()? as u64
            } else {
                reader.read_u64::<LE>()?
            })
        };

        let offset = var_int(31)?;
        let uncompressed_size = var_int(30)?;
        let compressed_size = match compression_method {
            Compression::None => uncompressed_size,
            _ => var_int(29)?,
        };

        block_uncompressed_size = if compression_block_count == 0 {
            0
        } else if uncompressed_size < block_uncompressed_size.into() {
            uncompressed_size.try_into().unwrap()
        } else {
            block_uncompressed_size
        };

        let offset_base = match version >= VersionMajor::RelativeChunkOffsets {
            true => 0,
            false => offset,
        } + serialized_size(
            version,
            compression_method,
            offset,
            compressed_size,
            uncompressed_size,
            compression_block_count,
            is_encrypted,
        );

        let blocks = if compression_block_count == 1 && !is_encrypted {
            Some(vec![Block {
                start: offset_base,
                end: offset_base + compressed_size,
            }])
        } else if compression_block_count > 0 {
            let mut index = offset_base;
            Some(
                (0..compression_block_count)
                    .map(|_| {
                        let mut block_size = reader.read_u32::<LE>()? as u64;
                        let block = Block {
                            start: index,
                            end: index + block_size,
                        };
                        if is_encrypted {
                            block_size = align(block_size);
                        }
                        index += block_size;
                        Ok(block)
                    })
                    .collect::<Result<Vec<_>, UnrealpakError>>()?,
            )
        } else {
            None
        };

        Ok(Record {
            offset,
            compressed_size,
            uncompressed_size,
            timestamp: None,
            compression_method,
            blocks,
            is_encrypted: Some(is_encrypted),
            compression_block_size: Some(block_uncompressed_size),
            hash: None,
        })
    } else {
        todo!()
    }
}

fn align(offset: u64) -> u64 {
    // add alignment (aes block size: 16) then zero out alignment bits
    (offset + 15) & !15
}

#[derive(Debug)]
pub(crate) enum EntryLocation {
    Data,
    Index,
}

pub(crate) fn write_record<W: Write>(
    writer: &mut W,
    version: VersionMajor,
    record: &Record,
    location: EntryLocation,
) -> Result<(), UnrealpakError> {
    if version >= VersionMajor::PathHashIndex {
        let compression_block_size = record.compression_block_size.unwrap_or_default();
        let compression_blocks_count = if let Some(b) = &record.blocks {
            b.len() as u32
        } else {
            0
        };
        let is_encrypted = record.is_encrypted.unwrap_or(false);
        let compression_method = record.compression_method as u32;
        let is_size_32_bit_safe = record.compressed_size <= u32::MAX as u64;
        let is_uncompressed_size_32_bit_safe = record.uncompressed_size <= u32::MAX as u64;
        let is_offset_32_bit_safe = record.offset <= u32::MAX as u64;

        let flags = (compression_block_size)
            | (compression_blocks_count << 6)
            | ((is_encrypted as u32) << 22)
            | ((compression_method as u32) << 23)
            | ((is_size_32_bit_safe as u32) << 29)
            | ((is_uncompressed_size_32_bit_safe as u32) << 30)
            | ((is_offset_32_bit_safe as u32) << 31);

        writer.write_u32::<LE>(flags)?;

        if is_offset_32_bit_safe {
            writer.write_u32::<LE>(record.offset as u32)?;
        } else {
            writer.write_u64::<LE>(record.offset)?;
        }

        if is_uncompressed_size_32_bit_safe {
            writer.write_u32::<LE>(record.uncompressed_size as u32)?
        } else {
            writer.write_u64::<LE>(record.uncompressed_size)?
        }

        if record.compression_method != Compression::None {
            if is_size_32_bit_safe {
                writer.write_u32::<LE>(record.compressed_size as u32)?;
            } else {
                writer.write_u64::<LE>(record.compressed_size)?;
            }

            assert!(record.blocks.is_some());
            let blocks = record.blocks.as_ref().unwrap();
            if blocks.len() > 1 || (blocks.len() == 1 && record.is_encrypted.unwrap()) {
                for b in blocks {
                    let block_size = b.end - b.start;
                    writer.write_u64::<LE>(block_size)?
                }
            }
        }

        Ok(())
    } else {
        writer.write_u64::<LE>(match location {
            EntryLocation::Data => 0,
            EntryLocation::Index => record.offset,
        })?;
        writer.write_u64::<LE>(record.compressed_size)?;
        writer.write_u64::<LE>(record.uncompressed_size)?;
        let compression: u8 = match record.compression_method {
            Compression::None => 0,
            Compression::Zlib => 1,
            Compression::Gzip => todo!(),
            Compression::Oodle => todo!(),
        };

        writer.write_u32::<LE>(compression.into())?;

        if version == VersionMajor::Initial {
            writer.write_u64::<LE>(record.timestamp.unwrap_or_default())?;
        }

        if let Some(hash) = &record.hash {
            writer.write_all(&hash.0)?;
        } else {
            panic!("hash missing");
        }

        if version >= VersionMajor::CompressionEncryption {
            if let Some(blocks) = &record.blocks {
                for block in blocks {
                    write_block(writer, block)?;
                }
            }
            writer.write_bool(record.is_encrypted.unwrap())?;
            writer.write_u32::<LE>(record.compression_block_size.unwrap_or_default())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_read_encoded_record_pack_v11() {
        let mut v11_encoded_record = [
            0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x54, 0x02, 0x00, 0x00,
        ];
        let mut reader = Cursor::new(&mut v11_encoded_record);
        let parsed_record = read_record(&mut reader, VersionMajor::Fnv64BugFix).unwrap();
        assert_eq!(parsed_record.offset, 0);
        assert_eq!(
            parsed_record.uncompressed_size,
            u64::from_le_bytes([0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        );
        assert_eq!(parsed_record.compression_method, Compression::None);
        assert_eq!(
            parsed_record.compressed_size,
            u64::from_le_bytes([0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        );
        assert_eq!(parsed_record.timestamp, None);
        assert_eq!(parsed_record.is_encrypted, Some(false));
        assert_eq!(parsed_record.compression_block_size, Some(0));
    }
}
