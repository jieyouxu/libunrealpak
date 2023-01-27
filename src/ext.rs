use crate::UnrealpakError;
use byteorder::{ReadBytesExt, WriteBytesExt, LE};
use std::io::{Read, Write};

pub trait ReadExt {
    fn read_bool(&mut self) -> Result<bool, UnrealpakError>;
    fn read_hash(&mut self) -> Result<[u8; 20], UnrealpakError>;
    fn read_array<T>(
        &mut self,
        func: impl FnMut(&mut Self) -> Result<T, UnrealpakError>,
    ) -> Result<Vec<T>, UnrealpakError>;
    fn read_cstring(&mut self) -> Result<String, UnrealpakError>;
    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, UnrealpakError>;
}

pub trait WriteExt {
    fn write_bool(&mut self, value: bool) -> Result<(), UnrealpakError>;
    fn write_cstring(&mut self, value: &str) -> Result<(), UnrealpakError>;
}

impl<R: Read> ReadExt for R {
    fn read_bool(&mut self) -> Result<bool, UnrealpakError> {
        match self.read_u8()? {
            1 => Ok(true),
            0 => Ok(false),
            err => Err(UnrealpakError::Bool(err)),
        }
    }

    fn read_hash(&mut self) -> Result<[u8; 20], UnrealpakError> {
        let mut guid = [0; 20];
        self.read_exact(&mut guid)?;
        Ok(guid)
    }

    fn read_array<T>(
        &mut self,
        mut func: impl FnMut(&mut Self) -> Result<T, UnrealpakError>,
    ) -> Result<Vec<T>, UnrealpakError> {
        let mut buf = Vec::with_capacity(self.read_u32::<LE>()? as usize);
        for _ in 0..buf.capacity() {
            buf.push(func(self)?);
        }
        Ok(buf)
    }

    fn read_cstring(&mut self) -> Result<String, UnrealpakError> {
        let mut buf = match self.read_i32::<LE>()? {
            size if size.is_negative() => {
                let mut buf = Vec::with_capacity(-size as usize);
                for _ in 0..buf.capacity() {
                    buf.push(self.read_u16::<LE>()?);
                }
                String::from_utf16(&buf)?
            }
            size => String::from_utf8(self.read_len(size as usize)?)?,
        };
        // remove the null byte
        buf.pop();
        Ok(buf)
    }

    fn read_len(&mut self, len: usize) -> Result<Vec<u8>, UnrealpakError> {
        let mut buf = vec![0; len];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

impl<W: Write> WriteExt for W {
    fn write_bool(&mut self, value: bool) -> Result<(), UnrealpakError> {
        self.write_u8(match value {
            true => 1,
            false => 0,
        })?;
        Ok(())
    }

    fn write_cstring(&mut self, value: &str) -> Result<(), UnrealpakError> {
        let bytes = value.as_bytes();
        self.write_u32::<LE>(bytes.len() as u32 + 1)?;
        self.write_all(bytes)?;
        self.write_u8(0)?;
        Ok(())
    }
}
