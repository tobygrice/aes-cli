use super::error::{Error, Result};
use super::mode::*;
use super::util::random_iv;

pub fn encrypt(plaintext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => encrypt_ecb(plaintext, key),
        Mode::ModeCTR => {
            // generate IV and prepend to ciphertext
            let iv = random_iv()?;
            let mut ciphertext: Vec<u8> = iv.to_vec();
            ciphertext.append(&mut ctr(plaintext, key, &iv, 0)?);
            Ok(ciphertext)
        }
        Mode::ModeGCM => {
            let iv = random_iv()?;
            let mut out: Vec<u8> = iv.to_vec();

            // prepend AAD len and AAD (currently no option for AAD implemented)
            out.extend_from_slice(&0u32.to_be_bytes());
            // out.extend_from_slice(aad);

            // compute ciphertext and tag
            let mut ct = ctr(plaintext, key, &iv, 2)?;
            let tag = compute_tag(&ct, key, &iv, &[])?; // AAD is empty for now

            out.append(&mut ct);
            out.extend_from_slice(&tag);
            Ok(out)
        }
    }
}

pub fn decrypt(ciphertext: &[u8], key: &[u8], mode: Mode) -> Result<Vec<u8>> {
    match mode {
        Mode::ModeECB => decrypt_ecb(ciphertext, key),
        Mode::ModeCTR => {
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

            ctr(ciphertext, key, &iv, 0)
        }
        Mode::ModeGCM => {
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

            // extract aad, ciphertext, and tag
            let (aad, ciphertext) = ciphertext.split_at(aad_len as usize);
            let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - 16);

            // format tag to [u8; 16]
            let mut received_tag = [0u8; 16];
            received_tag.copy_from_slice(tag_bytes);

            let computed_tag = compute_tag(ct, key, &iv, aad)?;
            if received_tag != computed_tag {
                return Err(Error::AuthFailed);
            }

            // run ctr starting at 2, as per NIST spec
            ctr(ct, key, &iv, 2)
        }
    }
}
