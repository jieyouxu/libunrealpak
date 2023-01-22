use byteorder::{ReadBytesExt, WriteBytesExt, LE};

use crate::{Version, MAGIC};

/// Footer of the `.pak` archive.
#[derive(Debug, Clone, PartialEq)]
pub enum Footer {
    V3AndBelow {
        common: FooterCommon,
    },
    V4ToV6 {
        is_encrypted: bool,
        common: FooterCommon,
    },
    V7 {
        is_encrypted: bool,
        encryption_uuid: u128,
        common: FooterCommon,
    },
    V8 {
        is_encrypted: bool,
        encryption_uuid: u128,
        common: FooterCommon,
        compression_methods: Box<[u8]>,
    },
    V9 {
        is_encrypted: bool,
        encryption_uuid: u128,
        common: FooterCommon,
        is_frozen_index: bool,
        compression_methods: Box<[u8]>,
    },
}

/// Common footer properties shared by all known `.pak` versions.
#[derive(Debug, Clone, PartialEq)]
pub struct FooterCommon {
    pub magic: u32,
    pub version: Version,
    pub index_offset: u64,
    pub index_size: u64,
    pub index_hash: [u8; 20],
}

pub fn read_footer<R: std::io::Read>(
    reader: &mut R,
    guess_version: Version,
) -> Result<Footer, crate::Error> {
    let encryption_uuid = if guess_version.major_version() >= 7 {
        Some(reader.read_u128::<LE>()?)
    } else {
        None
    };

    let is_encrypted = if guess_version.major_version() >= 4 {
        Some(read_bool(reader)?)
    } else {
        None
    };

    let magic = reader.read_u32::<LE>()?;
    if magic != MAGIC {
        return Err(crate::Error::MagicMismatch(magic, MAGIC));
    }

    let version = reader.read_u32::<LE>()?;
    let version = match version {
        1 => Version::V1,
        2 => Version::V2,
        3 => Version::V3,
        4 => Version::V4,
        5 => Version::V5,
        6 => Version::V6,
        7 => Version::V7,
        8 if guess_version == Version::V8A => Version::V8A,
        8 if guess_version == Version::V8B => Version::V8B,
        9 => Version::V9,
        10 => Version::V10,
        11 => Version::V11,
        _ => {
            return Err(crate::Error::VersionMismatch(
                version,
                guess_version.major_version(),
            ))
        }
    };
    if version != guess_version {
        return Err(crate::Error::VersionMismatch(
            version.major_version(),
            guess_version.major_version(),
        ));
    }

    let index_offset = reader.read_u64::<LE>()?;
    let index_size = reader.read_u64::<LE>()?;

    let mut index_hash = [0u8; 20];
    reader.read_exact(&mut index_hash)?;

    let is_frozen_index = if guess_version.major_version() == 9 {
        Some(read_bool(reader)?)
    } else {
        None
    };

    let compression_method = if guess_version.major_version() == 8 {
        let mut cm = [0u8; 128];
        reader.read_exact(&mut cm)?;
        Some(Vec::from(cm).into_boxed_slice())
    } else if guess_version.major_version() > 8 {
        let mut cm = [0u8; 160];
        reader.read_exact(&mut cm)?;
        Some(Vec::from(cm).into_boxed_slice())
    } else {
        None
    };

    Ok(match version {
        Version::V1 | Version::V2 | Version::V3 => Footer::V3AndBelow {
            common: FooterCommon {
                magic,
                version,
                index_offset,
                index_size,
                index_hash,
            },
        },
        Version::V4 | Version::V5 | Version::V6 => Footer::V4ToV6 {
            is_encrypted: is_encrypted.unwrap(),
            common: FooterCommon {
                magic,
                version,
                index_offset,
                index_size,
                index_hash,
            },
        },
        Version::V7 => Footer::V7 {
            is_encrypted: is_encrypted.unwrap(),
            encryption_uuid: encryption_uuid.unwrap(),
            common: FooterCommon {
                magic,
                version,
                index_offset,
                index_size,
                index_hash,
            },
        },
        Version::V8A | Version::V8B => Footer::V8 {
            is_encrypted: is_encrypted.unwrap(),
            encryption_uuid: encryption_uuid.unwrap(),
            common: FooterCommon {
                magic,
                version,
                index_offset,
                index_size,
                index_hash,
            },
            compression_methods: compression_method.unwrap(),
        },
        Version::V9 => Footer::V9 {
            is_encrypted: is_encrypted.unwrap(),
            encryption_uuid: encryption_uuid.unwrap(),
            common: FooterCommon {
                magic,
                version,
                index_offset,
                index_size,
                index_hash,
            },
            is_frozen_index: is_frozen_index.unwrap(),
            compression_methods: compression_method.unwrap(),
        },
        Version::V10 | Version::V11 => unimplemented!(),
    })
}

fn read_bool<R: std::io::Read>(reader: &mut R) -> Result<bool, crate::Error> {
    let b = reader.read_u8()?;
    let b = match b {
        0 => false,
        1 => true,
        _ => {
            return Err(crate::Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid bool value",
            )));
        }
    };
    Ok(b)
}

pub fn write_footer<W: std::io::Write>(writer: &mut W, f: &Footer) -> Result<(), crate::Error> {
    Ok(match f {
        Footer::V3AndBelow { common } => {
            write_footer_common(writer, common)?;
        }
        Footer::V4ToV6 {
            is_encrypted,
            common,
        } => {
            writer.write_u8(*is_encrypted as u8)?;
            write_footer_common(writer, common)?;
        }
        Footer::V7 {
            is_encrypted,
            encryption_uuid,
            common,
        } => {
            writer.write_u8(*is_encrypted as u8)?;
            writer.write_u128::<LE>(*encryption_uuid)?;
            write_footer_common(writer, common)?;
        }
        Footer::V8 {
            is_encrypted,
            encryption_uuid,
            common,
            compression_methods,
        } => {
            writer.write_u8(*is_encrypted as u8)?;
            writer.write_u128::<LE>(*encryption_uuid)?;
            write_footer_common(writer, common)?;
            writer.write_all(&compression_methods)?;
        }
        Footer::V9 {
            is_encrypted,
            encryption_uuid,
            common,
            is_frozen_index,
            compression_methods,
        } => {
            writer.write_u8(*is_encrypted as u8)?;
            writer.write_u128::<LE>(*encryption_uuid)?;
            write_footer_common(writer, common)?;
            writer.write_u8(*is_frozen_index as u8)?;
            writer.write_all(&compression_methods)?;
        }
    })
}

fn write_footer_common<W: std::io::Write>(
    writer: &mut W,
    f: &FooterCommon,
) -> Result<(), crate::Error> {
    writer.write_u32::<LE>(f.magic)?;
    writer.write_u32::<LE>(f.version.major_version())?;
    writer.write_u64::<LE>(f.index_offset)?;
    writer.write_u64::<LE>(f.index_size)?;
    writer.write_all(&f.index_hash)?;
    Ok(())
}
