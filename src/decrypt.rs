use crate::errors::UnrealpakError;

pub(crate) fn decrypt(
    key: &Option<aes::Aes256Dec>,
    bytes: &mut [u8],
) -> Result<(), UnrealpakError> {
    if let Some(key) = &key {
        use aes::cipher::BlockDecrypt;
        for chunk in bytes.chunks_mut(16) {
            key.decrypt_block(aes::Block::from_mut_slice(chunk))
        }
        Ok(())
    } else {
        Err(UnrealpakError::Encrypted)
    }
}
