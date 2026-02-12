use crate::aes_lib::error::{Error, Result};
use crate::aes_lib::key::{Key, expand_key};
use crate::aes_lib::mode::encrypt_ecb_core;

use crate::aes_lib::mode::*;
use crate::aes_lib::util::random_iv;

pub struct Cipher {
    round_keys: Vec<[u8; 16]>,
}

impl Cipher {
    pub fn new(key: &Key) -> Self {
        Self {
            round_keys: expand_key(key),
        }
    }

    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_ecb_core(plaintext, &self.round_keys)
    }

    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_ecb_core(ciphertext, &self.round_keys)
    }

    pub fn encrypt_ctr(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // generate IV and prepend to ciphertext
        let iv = random_iv()?;
        let mut ciphertext: Vec<u8> = iv.to_vec();
        ciphertext.append(&mut ctr_core(plaintext, &self.round_keys, &iv, 0)?);
        Ok(ciphertext)
    }

    pub fn decrypt_ctr(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // extract and remove IV from ciphertext
        if ciphertext.len() < 12 {
            return Err(Error::InvalidCiphertext {
                len: ciphertext.len(),
                context: "CTR: missing 12-byte IV",
            });
        }

        let (iv_bytes, ciphertext) = ciphertext.split_at(12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(iv_bytes);

        ctr_core(ciphertext, &self.round_keys, &iv, 0)
    }

    pub fn encrypt_gcm(&self, plaintext: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
        let iv = random_iv()?;
        let mut out: Vec<u8> = iv.to_vec();

        // prepend AAD len and AAD
        let aad_bytes = aad.unwrap_or(&[]);
        out.extend_from_slice(&(aad_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(aad_bytes);

        // compute ciphertext and tag
        let mut ct = ctr_core(plaintext, &self.round_keys, &iv, 2)?;
        let tag = compute_tag(&ct, &self.round_keys, &iv, aad_bytes)?;

        out.append(&mut ct);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    pub fn decrypt_gcm(&self, ciphertext: &[u8]) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
        // minimum size is 32 bytes -> 12 (iv) + 4 (aad_len) + 16 (tag)
        if ciphertext.len() < 32 {
            return Err(Error::InvalidCiphertext {
                len: ciphertext.len(),
                context: "insufficient bytes for valid GCM",
            });
        }

        // extract IV
        let (iv_bytes, ciphertext) = ciphertext.split_at(12);
        let mut iv = [0u8; 12];
        iv.copy_from_slice(iv_bytes);

        // extract AAD len and validate remaining size
        let (aad_len, ciphertext) = ciphertext.split_at(4);
        let aad_len = u32::from_be_bytes([aad_len[0], aad_len[1], aad_len[2], aad_len[3]]);
        if ciphertext.len() < aad_len as usize + 16 {
            return Err(Error::InvalidCiphertext {
                len: ciphertext.len(),
                context: "insufficient bytes given aad_len",
            });
        }

        // extract aad and save in vector
        let (aad, ciphertext) = ciphertext.split_at(aad_len as usize);
        let aad = aad.to_vec();

        // extract tag and format as [u8; 16]
        let mut received_tag = [0u8; 16];
        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);
        received_tag.copy_from_slice(tag_bytes);

        // compute and compare tag
        let computed_tag = compute_tag(ct, &self.round_keys, &iv, &aad)?;
        if received_tag != computed_tag {
            return Err(Error::AuthFailed);
        }

        // wrap AAD in option
        let aad = if !aad.is_empty() { Some(aad) } else { None };

        // run ctr starting at 2, as per NIST spec
        let plaintext = ctr_core(ct, &self.round_keys, &iv, 2)?;
        Ok((plaintext, aad))
    }
}
