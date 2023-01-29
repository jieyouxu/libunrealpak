#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub enum Compression {
    None,
    Zlib,
    Gzip,
    Oodle,
}
