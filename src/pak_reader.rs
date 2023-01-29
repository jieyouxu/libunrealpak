use std::io::{Read, Seek, SeekFrom};

use aes::Aes256Dec;

use crate::errors::UnrealpakError;
use crate::footer::read_footer;
use crate::index::read_index;
use crate::pak::Pak;
use crate::version::VersionMajor;

#[derive(Debug)]
pub struct PakReader<R> {
    pub(crate) pak: Pak,
    pub(crate) reader: R,
    pub(crate) key: Option<Aes256Dec>,
}

impl<R> PakReader<R>
where
    R: Read + Seek,
{
    pub fn read(
        mut reader: R,
        version: VersionMajor,
        key: Option<Aes256Dec>,
    ) -> Result<Self, UnrealpakError> {
        let pak = {
            // Read footer
            reader.seek(SeekFrom::End(-(version.footer_size() as i64)))?;
            let footer = read_footer(&mut reader, version)?;
            // Read index
            reader.seek(SeekFrom::Start(footer.index_offset))?;

            let index = read_index(
                &mut reader,
                footer.index_offset,
                footer.index_size,
                version,
                footer.is_index_encrypted.unwrap_or(false),
                key.clone(),
            )?;

            Pak { version, index }
        };

        Ok(PakReader { pak, reader, key })
    }

    pub fn read_any(mut reader: R, key: Option<Aes256Dec>) -> Result<Self, UnrealpakError> {
        // Try parsing from newest versions first.
        for &v in VersionMajor::iterator().rev() {
            if let Ok(pak) = PakReader::read(&mut reader, v, key.clone()) {
                return Ok(PakReader {
                    pak: pak.pak,
                    reader,
                    key,
                });
            }
        }
        Err(UnrealpakError::UnsupportedVersion)
    }

    pub fn files(&self) -> impl Iterator<Item = String> {
        let mut fs = vec![];
        let fdi = self.pak.index.full_directory_index.as_ref().unwrap();
        for (directory, files) in fdi.0.iter() {
            for (filename, _) in files.iter() {
                let path = if directory == "/" {
                    filename.to_owned()
                } else {
                    directory.clone() + filename
                };
                fs.push(path);
            }
        }
        fs.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use crate::index::Index;

    use super::*;

    #[test]
    fn test_read_pak_pack_v11() {
        let mut v11_pack = include_bytes!("../tests/packs/pack_v11.pak");
        let reader = Cursor::new(&mut v11_pack);
        let pak = PakReader::read(reader, VersionMajor::Fnv64BugFix, None).unwrap();
        assert_eq!(
            pak.files().collect::<Vec<_>>(),
            vec!["test.png", "test.txt", "zeros.bin", "directory/nested.txt"]
        );
        assert_eq!(pak.pak.index.mount_point, "../mount/point/root/".to_owned());
    }
}
