use crate::aes_lib::error::{Error, Result};
use crate::aes_lib::key::Key;
use crate::aes_lib::mode::encrypt_ecb_core;

use crate::aes_lib::core::constants::{RCON, SBOX};
use crate::aes_lib::util::xor_words;

use crate::aes_lib::mode::*;
use crate::aes_lib::util::random_iv;

/// Provides encryption and decryption functions for AES in modes [ECB](crate::Cipher::encrypt_ecb), [CTR](crate::Cipher::encrypt_ctr), and [GCM](crate::Cipher::encrypt_gcm).
/// Instantiated with an AES [Key], which is expanded into round keys and stored in the instance.
pub struct Cipher {
    round_keys: Vec<[u8; 16]>,
}

impl Cipher {
    /// Generates round keys from provided key and stores in the returned instance.
    pub fn new(key: &Key) -> Self {
        Self {
            round_keys: Self::expand_key(key),
        }
    }

    /// Getter for internal round keys. Returned as a slice of 16-byte arrays.
    pub fn get_round_keys(&self) -> &[[u8; 16]] {
        &self.round_keys
    }

    /// **Electronic codebook** encryption.
    ///
    /// Encrypts each 16-byte block entirely independently
    /// and chains them together. **Vulnerable to pattern emergence in the ciphertext.**
    pub fn encrypt_ecb(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        encrypt_ecb_core(plaintext, &self.round_keys)
    }

    /// **Electronic codebook** decryption.
    pub fn decrypt_ecb(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        decrypt_ecb_core(ciphertext, &self.round_keys)
    }

    /// **Counter mode** encryption.
    ///
    /// Generates a random 12-byte initialisation vector (IV).
    /// For each 16-byte block of plaintext:
    /// 1. 4-byte counter is incremented (starts at zero).
    /// 2. Counter is appended to 12-byte IV to form a 16-byte block.
    /// 3. The `IV || Counter` block is encrypted using the round keys.
    /// 4. The plaintext block is `XOR`'d with the encrypted counter block.
    ///
    /// **Important**: the same IV must never be reused with the same key. 96 bits is
    /// sufficiently large to assume uniqueness when randomly generated.
    ///
    /// Output is formatted as `IV (12 bytes) || Ciphertext`
    pub fn encrypt_ctr(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // generate IV and prepend to ciphertext
        let iv = random_iv()?;
        let mut ciphertext: Vec<u8> = iv.to_vec();
        ciphertext.append(&mut ctr_core(plaintext, &self.round_keys, &iv, 0)?);
        Ok(ciphertext)
    }

    /// **Counter mode** decryption.
    ///
    /// Assumes format matches output of encryption: `IV (12 bytes) || Ciphertext`
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

    /// **Galois/counter mode** encryption.
    ///
    /// Encrypts using counter mode and generates a cryptographic tag to verify the
    /// message has not been modified.
    ///
    /// Also accepts optional additional authenticated data (AAD), which is included in the computation of the
    /// tag but **not encrypted**.
    ///
    /// Output is formatted as `IV (12 bytes) || AAD length (4 bytes) || AAD || Ciphertext || Tag (16 bytes)`
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

    /// **Galois/counter mode** decryption.
    ///
    /// Assumes input follows the same format as [encryption](crate::aes_lib::cipher::Cipher::encrypt_gcm):
    /// `IV (12 bytes) || AAD length (4 bytes) || AAD || Ciphertext || Tag (16 bytes)`
    ///
    /// Returns:
    /// - `(plaintext, AAD)` if tag was authenticated and decryption was successful.
    /// - [AuthFailed](crate::Error::AuthFailed) error if computed tag did not match input tag.
    /// - [CounterOverflow](crate::Error::CounterOverflow) error if more than 2^32 blocks were provided.
    /// - [InvalidCiphertext](crate::Error::InvalidCiphertext) error if ciphertext does not match expected format.
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

    /// AES key schedule. Returns a vector of 11, 13, or 15 round keys, corresponding with AES-128, AES-192,
    /// and AES-256, respectively. The extra round key is the initial round key, which is not counted in most 
    /// documentation as it is simply the original key.
    fn expand_key(key: &Key) -> Vec<[u8; 16]> {
        let key = key.as_bytes();

        // Variable names match FIPS-197, NIST specification: https://doi.org/10.6028/NIST.FIPS.197-upd1
        // Nk   The number of 32-bit words comprising the key
        // Nr   The number of rounds. 10, 12, and 14 for AES-128, AES-192, and AES-256, respectively
        // w    The result of the key schedule, an array of words that form round keys
        // Nw   The total number of words generated by the key schedule (including initial key)
        let nk = key.len() / 4; // key size (in 4-byte words)
        let nr = nk + 6; // number of rounds = num of words in key + 6
        let nw = (nr + 1) * 4; // total number of words resulting from expansion

        // initialise w, vector comprising 4-byte words of round_keys
        let mut w: Vec<[u8; 4]> = vec![[0u8; 4]; nw];

        // first nk words of w are filled with the initial key
        for i in 0..key.len() {
            w[i / 4][i % 4] = key[i];
        }

        // initialise temp variable
        let mut temp = w[nk - 1];
        for i in nk..nw {
            if i % nk == 0 {
                // calculate rot_word, sub_word, and rcon on temp
                temp = [
                    SBOX[temp[1] as usize] ^ RCON[i / nk],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                    SBOX[temp[0] as usize],
                ];
            } else if nk == 8 && i % nk == 4 {
                // additional substitution on temp for AES-256 only
                temp = [
                    SBOX[temp[0] as usize],
                    SBOX[temp[1] as usize],
                    SBOX[temp[2] as usize],
                    SBOX[temp[3] as usize],
                ];
            }

            // w[i] = temp ⊕ w[i − Nk]
            w[i] = xor_words(&temp, &w[i - nk]);
            temp = w[i]; // update temp
        }

        // convert words vector into indexable round_keys vector
        let mut round_keys = vec![[0u8; 16]; nr + 1];
        for round in 0..=nr {
            let base = round * 4;
            for col in 0..4 {
                let word = w[base + col];
                for row in 0..4 {
                    round_keys[round][col * 4 + row] = word[row];
                }
            }
        }

        round_keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_schedule_128() -> Result<()> {
        // run key schedule on 128 bit sample key from FIPS-197 Appendix A.1
        let key_128: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];

        let key = Key::try_from_slice(&key_128)?;
        let round_keys = Cipher::expand_key(&key);
        let last = *round_keys.last().expect("round_keys should not be empty");

        // compare with last round key of sample schedule in A.1
        let expected: [u8; 16] = [
            0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63,
            0x0c, 0xa6,
        ];

        assert_eq!(last, expected);

        Ok(())
    }

    #[test]
    fn key_schedule_192() -> Result<()> {
        // run key schedule on 192 bit sample key from FIPS-197 Appendix A.2
        let key_192: [u8; 24] = [
            0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90,
            0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b,
        ];

        let key = Key::try_from_slice(&key_192)?;
        let round_keys = Cipher::expand_key(&key);
        let last = *round_keys.last().expect("round_keys should not be empty");

        // compare with last round key of sample schedule in A.2
        let expected: [u8; 16] = [
            0xe9, 0x8b, 0xa0, 0x6f, 0x44, 0x8c, 0x77, 0x3c, 0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00,
            0x22, 0x02,
        ];

        assert_eq!(last, expected);

        Ok(())
    }

    #[test]
    fn key_schedule_256() -> Result<()> {
        // run key schedule on 256 bit sample key from FIPS-197 Appendix A.3
        let key_256: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];

        let key = Key::try_from_slice(&key_256)?;
        let round_keys = Cipher::expand_key(&key);
        let last = *round_keys.last().expect("round_keys should not be empty");

        // compare with last round key of sample schedule in A.3
        let expected: [u8; 16] = [
            0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c,
            0x63, 0x1e,
        ];

        assert_eq!(last, expected);

        Ok(())
    }

    #[test]
    fn example_test() {
        // generate a random 256-bit key.
        let key = Key::rand_key_256().expect("Random key generation failed");

        // instantiate a cipher object using that key.
        let cipher = Cipher::new(&key);

        // instantiate sample plaintext (cipher encrypts raw bytes).
        let plaintext = ("Hello, World!").as_bytes();

        // encrypt the plaintext bytes using AES-256-CTR.
        // note that the key size does not need to be explicitly stated.
        let ciphertext = cipher.encrypt_ctr(&plaintext).expect("Counter overflow");

        // decrypt the resultant ciphertext.
        let decrypted_ct = cipher.decrypt_ctr(&ciphertext).expect("Counter overflow");

        // round trip results in the same plaintext as the original message.
        assert_eq!(plaintext, decrypted_ct);
    }
}
