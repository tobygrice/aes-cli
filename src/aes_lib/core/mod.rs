//! Core AES implementation for encryption and decryption of a 16 byte block. Exports encrypt_block and decrypt_block.

pub mod constants;
mod core_util;
mod decryption;
mod encryption;

pub use decryption::decrypt_block;
pub use encryption::encrypt_block;
