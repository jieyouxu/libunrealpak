//! There are two versions: legacy Fnv64 and current Fnv64.
//! Ported from <https://github.com/EpicGames/UnrealEngine/blob/cdaec5b33ea5d332e51eee4e4866495c90442122/Engine/Source/Runtime/Core/Private/Misc/Fnv.cpp#L26>.

use std::io::Read;

use byteorder::ReadBytesExt;

use crate::errors::UnrealpakError;

pub(crate) fn fnv64(data: &[u8], offset: u64) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET + offset;
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}
