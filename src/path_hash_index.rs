use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use crate::errors::UnrealpakError;
use crate::ext::ReadExt;
use std::io::{Read, Write};

/// Hash and EncodedRecord offset entries.
#[derive(Debug, PartialEq)]
pub(crate) struct PathHashIndex(pub(crate) Vec<(u64, u32)>);

impl PathHashIndex {
    pub(crate) fn serialized_size(&self) -> u64 {
        let mut size = 0;
        size += 4; // u32 count
        for (_hash, _offset) in &self.0 {
            size += 8; // u64 hash
            size += 4; // u32 offset
        }
        size += 4; // unknown padding bytes
        size
    }
}

pub(crate) fn read_path_hash_index<R: Read>(
    reader: &mut R,
) -> Result<PathHashIndex, UnrealpakError> {
    let n_entries = reader.read_u32::<LE>()?;
    let mut phi = Vec::with_capacity(n_entries as usize);
    for _ in 0..n_entries {
        let hash = reader.read_u64::<LE>()?;
        let offset = reader.read_u32::<LE>()?;
        phi.push((hash, offset));
    }
    let _padding = reader.read_u32::<LE>()?;
    debug_assert!(_padding == 0);
    Ok(PathHashIndex(phi))
}

pub(crate) fn write_path_hash_index<W: Write>(
    writer: &mut W,
    phi: &PathHashIndex,
) -> Result<(), UnrealpakError> {
    writer.write_u32::<LE>(phi.0.len() as u32)?;
    for (hash, offset) in &phi.0 {
        writer.write_u64::<LE>(*hash)?;
        writer.write_u32::<LE>(*offset)?;
    }
    writer.write_u32::<LE>(0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_path_hash_index_pack_v11() {
        let mut phi = [
            0x04, 0x00, 0x00, 0x00, 0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7, 0x00, 0x00,
            0x00, 0x00, 0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20, 0x0C, 0x00, 0x00, 0x00,
            0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50, 0x18, 0x00, 0x00, 0x00, 0xD0, 0x75,
            0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut reader = Cursor::new(&mut phi);
        let parsed_phi = read_path_hash_index(&mut reader).unwrap();
        assert_eq!(parsed_phi.serialized_size(), phi.len() as u64);

        let expected_phi = PathHashIndex(vec![
            (
                u64::from_le_bytes([0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]),
                0x00,
            ),
            (
                u64::from_le_bytes([0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20]),
                0x0C,
            ),
            (
                u64::from_le_bytes([0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50]),
                0x18,
            ),
            (
                u64::from_le_bytes([0xD0, 0x75, 0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32]),
                0x24,
            ),
        ]);

        assert_eq!(parsed_phi, expected_phi);
    }

    #[test]
    fn test_write_path_hash_index_pack_v11() {
        let expected_bytes = [
            0x04, 0x00, 0x00, 0x00, 0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7, 0x00, 0x00,
            0x00, 0x00, 0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20, 0x0C, 0x00, 0x00, 0x00,
            0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50, 0x18, 0x00, 0x00, 0x00, 0xD0, 0x75,
            0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let phi = PathHashIndex(vec![
            (
                u64::from_le_bytes([0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]),
                0x00,
            ),
            (
                u64::from_le_bytes([0xC3, 0x7F, 0x05, 0x13, 0xB5, 0x4B, 0x70, 0x20]),
                0x0C,
            ),
            (
                u64::from_le_bytes([0xEA, 0x72, 0xA1, 0x2B, 0x36, 0x79, 0x5F, 0x50]),
                0x18,
            ),
            (
                u64::from_le_bytes([0xD0, 0x75, 0xA6, 0x65, 0x98, 0xD6, 0x61, 0x32]),
                0x24,
            ),
        ]);

        let mut actual_bytes = vec![];
        let mut writer = Cursor::new(&mut actual_bytes);
        write_path_hash_index(&mut writer, &phi).unwrap();

        assert_eq!(actual_bytes, expected_bytes);
    }
}
