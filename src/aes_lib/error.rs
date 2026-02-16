use thiserror::Error;
use rand::rand_core;

/// AES Result type.
pub type Result<T> = std::result::Result<T, Error>;

/// AES Error type. 
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Computed authentication tag did not match input tag. Ciphertext and/or AAD has been modified since it was encrypted.
    #[error("GCM authentication failed (invalid tag)")]
    AuthFailed,

    /// Attempted to encrypt or decrypt more than 2^32 16-byte blocks in GCM/CTR mode.
    #[error("input size caused counter overflow (maximum input size for 32 bit counter is 16 * 2^32 bytes)")]
    CounterOverflow,
    
    /// Attempted to instantiate an AES key with an input size that is not 128, 192, or 256 bits.
    #[error("invalid key length: {len} bytes (expected 16, 24, or 32)")]
    InvalidKeyLength { len: usize },

    /// Provided ciphertext that did not match the expected format of the mode of operation.
    #[error("invalid ciphertext length: {len} bytes ({context})")]
    InvalidCiphertext { len: usize, context: &'static str },

    /// OS RNG failed during random key generation.
    #[error("OS RNG failed in random key generation")]
    Rng(#[from] rand_core::OsError),

}
