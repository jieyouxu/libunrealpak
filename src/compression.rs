#[derive(Debug, Copy, Clone, PartialEq)]
#[repr(u32)]
pub(crate) enum Compression {
    None,
    Zlib,
    Gzip,
    Oodle,
}
