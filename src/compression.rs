#[derive(Debug, Copy, Clone, PartialEq)]
pub(crate) enum Compression {
    None,
    Zlib,
    Gzip,
    Oodle,
}
