use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::aes_lib::error::{Error, Result};

#[derive(Clone)]
enum KeyBytes {
    K128([u8; 16]),
    K192([u8; 24]),
    K256([u8; 32]),
}

/// Contains a valid AES key. Can be instantiated with a random key, or built from a slice
/// of bytes that is 16, 24, or 32 bytes long.
/// A `key` object is required to instantiate a [Cipher](crate::Cipher).
#[derive(Clone)]
pub struct Key {
    bytes: KeyBytes,
}

impl Key {
    /// Generate a random 128-bit key. Returns Error if OsRng fails.
    pub fn rand_key_128() -> Result<Self> {
        let mut k = [0u8; 16];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K128(k),
        })
    }

    /// Generate a random 192-bit key. Returns Error if OsRng fails.
    pub fn rand_key_192() -> Result<Self> {
        let mut k = [0u8; 24];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K192(k),
        })
    }

    /// Generate a random 256-bit key. Returns Error if OsRng fails.
    pub fn rand_key_256() -> Result<Self> {
        let mut k = [0u8; 32];
        OsRng.try_fill_bytes(&mut k)?;
        Ok(Self {
            bytes: KeyBytes::K256(k),
        })
    }

    /// Attempts to build a key from a slice of bytes. Will return an InvalidKeyLength error
    /// if the input slice is anything other than 16, 24, or 32 bytes long.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(match bytes.len() {
            16 => Self {
                bytes: KeyBytes::K128(bytes.try_into().unwrap()), // match condition guarantees safe unwrap
            },
            24 => Self {
                bytes: KeyBytes::K192(bytes.try_into().unwrap()),
            },
            32 => Self {
                bytes: KeyBytes::K256(bytes.try_into().unwrap()),
            },
            _ => return Err(Error::InvalidKeyLength { len: bytes.len() }),
        })
    }

    /// Returns a reference to the internal key as an array of bytes.
    pub fn as_bytes(&self) -> &[u8] {
        match &self.bytes {
            KeyBytes::K128(k) => k,
            KeyBytes::K192(k) => k,
            KeyBytes::K256(k) => k,
        }
    }
}


