/// Test vectors for GCM. Test code from https://github.com/RustCrypto/AEADs/tree/master/aes-gcm/tests
#[derive(Debug)]
pub struct TestVector<K: 'static, N: 'static> {
    pub key: &'static K,
    pub nonce: &'static N,
    pub aad: &'static [u8],
    pub plaintext: &'static [u8],
    pub ciphertext: &'static [u8],
    pub tag: &'static [u8; 16],
}

pub fn pack_message(iv: &[u8; 12], aad: &[u8], ciphertext: &[u8], tag: &[u8; 16]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(12 + 4 + aad.len() + ciphertext.len() + 16);
    msg.extend_from_slice(iv);
    msg.extend_from_slice(&(aad.len() as u32).to_be_bytes());
    msg.extend_from_slice(aad);
    msg.extend_from_slice(ciphertext);
    msg.extend_from_slice(tag);
    msg
}

/// Generate encrypt/decrypt tests over the given NIST vectors.
#[macro_export]
macro_rules! gcm_tests {
    ($vectors:expr) => {
        #[test]
        fn nist_vectors_decrypt_ok() {
            for vector in $vectors {
                let key = Key::try_from_slice(vector.key)
                    .expect("invalid test key bytes for this implementation");

                let cipher = Cipher::new(&key);

                // Build message format: iv || aad_len || aad || ciphertext || tag
                let msg = crate::common::pack_message(vector.nonce, vector.aad, vector.ciphertext, vector.tag);

                let (pt, aad_out) = cipher
                    .decrypt_gcm(&msg)
                    .expect("valid NIST vector should decrypt");

                assert_eq!(vector.plaintext, pt.as_slice());

                let expected_aad = if vector.aad.is_empty() {
                    None
                } else {
                    Some(vector.aad.to_vec())
                };
                assert_eq!(expected_aad, aad_out);
            }
        }

        #[test]
        fn nist_vectors_reject_bad_tag() {
            for vector in $vectors {
                let key = Key::try_from_slice(vector.key)
                    .expect("invalid test key bytes for this implementation");
                let cipher = Cipher::new(&key);

                let mut msg = crate::common::pack_message(vector.nonce, vector.aad, vector.ciphertext, vector.tag);

                // Flip a bit in the tag (last byte)
                let last = msg.len() - 1;
                msg[last] ^= 0x01;

                assert!(cipher.decrypt_gcm(&msg).is_err());
            }
        }

        #[test]
        fn nist_vectors_reject_tampered_ciphertext_or_iv() {
            for vector in $vectors {
                let key = Key::try_from_slice(vector.key)
                    .expect("invalid test key bytes for this implementation");
                let cipher = Cipher::new(&key);

                let mut msg = crate::common::pack_message(vector.nonce, vector.aad, vector.ciphertext, vector.tag);

                // If ciphertext is non-empty, flip first ciphertext byte.
                // Otherwise flip IV[0] (still should fail tag check).
                let ct_offset = 12 + 4 + vector.aad.len();
                if !vector.ciphertext.is_empty() {
                    msg[ct_offset] ^= 0x01;
                } else {
                    msg[0] ^= 0x01;
                }

                assert!(cipher.decrypt_gcm(&msg).is_err());
            }
        }

        #[test]
        fn nist_vectors_encrypt_matches() {
            for vector in $vectors {
                let key = Key::try_from_slice(vector.key)
                    .expect("invalid test key bytes for this implementation");
                let cipher = Cipher::new(&key);

                let got = cipher.encrypt_gcm_with_iv(vector.plaintext, Some(vector.aad), vector.nonce).expect("encrypt should succeed");

                let expected = crate::common::pack_message(vector.nonce, vector.aad, vector.ciphertext, vector.tag);
                assert_eq!(expected, got);
            }
        }
    };
}
