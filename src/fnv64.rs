//! There are two versions: legacy Fnv64 and current Fnv64.
//! Ported from <https://github.com/EpicGames/UnrealEngine/blob/cdaec5b33ea5d332e51eee4e4866495c90442122/Engine/Source/Runtime/Core/Private/Misc/Fnv.cpp#L26>.

use std::io::Read;

use byteorder::ReadBytesExt;

use crate::errors::UnrealpakError;

pub(crate) fn fnv64(data: &[u8], offset: u64) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x00000100000001b3;
    let mut hash = OFFSET.wrapping_add(offset);
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

pub(crate) fn legacy_fnv64(data: &[u8], offset: u64) -> u64 {
    const OFFSET: u64 = 0x00000100000001b3;
    const PRIME: u64 = 0xcbf29ce484222325;
    let mut hash = OFFSET.wrapping_add(offset);
    for &b in data {
        hash ^= b as u64;
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_path_hash_index() {
        let input = b"directory/nested.txt";
        let path_hash_seed = u64::from_le_bytes([0x7D, 0x5A, 0x5C, 0x20, 0x00, 0x00, 0x00, 0x00]);

        let hash = fnv64(&input[..], path_hash_seed);
        let legacy_hash = legacy_fnv64(&input[..], path_hash_seed);

        eprintln!("hash = {:0X?}", hash.to_le_bytes());
        eprintln!("legacy_hash = {:0X?}", legacy_hash.to_le_bytes());
        eprintln!(
            "expected_path_hash = {:0X?}",
            [0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]
        );

        assert_eq!(
            hash.to_le_bytes(),
            [0x1F, 0x9E, 0x68, 0xA5, 0xCF, 0xC4, 0x78, 0xF7]
        );
    }
}
