use crate::errors::UnrealpakError;
use crate::ReadExt;
use crate::ext::WriteExt;
use byteorder::{ReadBytesExt, LE, WriteBytesExt};
use std::collections::BTreeMap;
use std::io::{Read, Write};

/// Map<DirectoryName, Map<FileName, Offset>>
#[derive(Debug, PartialEq)]
pub(crate) struct FullDirectoryIndex(BTreeMap<String, BTreeMap<String, u32>>);

pub(crate) fn read_full_directory_index<R: Read>(
    reader: &mut R,
) -> Result<FullDirectoryIndex, UnrealpakError> {
    let dir_count = reader.read_u32::<LE>()? as usize;
    let mut directories = BTreeMap::new();
    for _ in 0..dir_count {
        let dir_name = reader.read_cstring()?;
        let file_count = reader.read_u32::<LE>()? as usize;
        let mut files = BTreeMap::new();
        for _ in 0..file_count {
            let file_name = reader.read_cstring()?;
            files.insert(file_name, reader.read_u32::<LE>()?);
        }
        directories.insert(dir_name, files);
    }

    Ok(FullDirectoryIndex(directories))
}

pub(crate) fn write_full_directory_index<W: Write>(
    writer: &mut W,
    fdi: &FullDirectoryIndex,
) -> Result<(), UnrealpakError> {
    writer.write_u32::<LE>(fdi.0.len() as u32)?;
    for (directory, files) in &fdi.0 {
        writer.write_cstring(directory)?;
        writer.write_u32::<LE>(files.len() as u32)?;
        for (filename, offset) in files {
            writer.write_cstring(filename)?;
            writer.write_u32::<LE>(*offset)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_full_directory_index_pack_v11() {
        let mut v11_full_directory_index_bytes = [
            0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x70, 0x6E, 0x67, 0x00, 0x0C,
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78,
            0x74, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x7A, 0x65, 0x72, 0x6F,
            0x73, 0x2E, 0x62, 0x69, 0x6E, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00,
            0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x2F, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x6E, 0x65, 0x73, 0x74, 0x65, 0x64, 0x2E, 0x74, 0x78,
            0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(v11_full_directory_index_bytes.len(), 104);

        let mut reader = Cursor::new(&mut v11_full_directory_index_bytes);
        let parsed_fdi = read_full_directory_index(&mut reader).unwrap();

        let expected_fdi = FullDirectoryIndex({
            let mut fdi = BTreeMap::new();
            fdi.insert("/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("test.png".to_owned(), 0xC);
                files.insert("test.txt".to_owned(), 0x18);
                files.insert("zeros.bin".to_owned(), 0x24);
                files
            });
            fdi.insert("directory/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("nested.txt".to_owned(), 0x0);
                files
            });
            fdi
        });

        assert_eq!(parsed_fdi, expected_fdi);
    }

    #[test]
    fn test_write_full_directory_index_pack_v11() {
        let fdi = FullDirectoryIndex({
            let mut fdi = BTreeMap::new();
            fdi.insert("/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("test.png".to_owned(), 0xC);
                files.insert("test.txt".to_owned(), 0x18);
                files.insert("zeros.bin".to_owned(), 0x24);
                files
            });
            fdi.insert("directory/".to_owned(), {
                let mut files = BTreeMap::new();
                files.insert("nested.txt".to_owned(), 0x0);
                files
            });
            fdi
        });

        let mut written_bytes = vec![];
        let mut writer = Cursor::new(&mut written_bytes);
        write_full_directory_index(&mut writer, &fdi).unwrap();

        let expected_bytes = [
            0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x03, 0x00, 0x00, 0x00,
            0x09, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x70, 0x6E, 0x67, 0x00, 0x0C,
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x74, 0x78,
            0x74, 0x00, 0x18, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x7A, 0x65, 0x72, 0x6F,
            0x73, 0x2E, 0x62, 0x69, 0x6E, 0x00, 0x24, 0x00, 0x00, 0x00, 0x0B, 0x00, 0x00, 0x00,
            0x64, 0x69, 0x72, 0x65, 0x63, 0x74, 0x6F, 0x72, 0x79, 0x2F, 0x00, 0x01, 0x00, 0x00,
            0x00, 0x0B, 0x00, 0x00, 0x00, 0x6E, 0x65, 0x73, 0x74, 0x65, 0x64, 0x2E, 0x74, 0x78,
            0x74, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        assert_eq!(written_bytes, expected_bytes);
    }
}
