//! This crate provides an intuitive interface for AES-128, AES-192, and AES-256 encryption and decryption.
//! The following modes of operation are supported:
//! - **Galois/counter mode** ([GCM](crate::Cipher::encrypt_gcm)), with optional additional authenticated data (AAD). 
//! Encrypts using CTR mode and generates an authentication tag from the AAD + plaintext. This tag is recomputed at decryption 
//! and compared with the received tag.
//! - **Counter mode** ([CTR](crate::Cipher::encrypt_ctr)). A 16-byte counter is repeatedly incremented and encrypted. 
//! The result is `XOR`'d with the plaintext to produce the ciphertext. 
//! This turns AES into a stream cipher, which removes vulnerabilities present in modes such as ECB.  
//! - **Electronic codebook mode** ([ECB](crate::Cipher::encrypt_ecb)). Encrypts each block of plaintext seperately and appends to the output. 
//! Vulnerable to pattern emergence in larger inputs. Use a stream cipher mode (CTR or GCM) if security is important. 
//! 
//! ## Examples
//! Below is an example of a string being encrypted under a random key using AES-256-CTR, then decrypted back to plaintext.
//! ```
//! use aes::{Key, Cipher};
//! 
//! // generate a random 256-bit key.
//! let key = Key::rand_key_256().expect("Random key generation failed");
//! 
//! // instantiate a cipher object using that key.
//! let cipher = Cipher::new(&key);
//! 
//! // instantiate sample plaintext (cipher encrypts raw bytes).
//! let plaintext = ("Hello, World!").as_bytes();
//! 
//! // encrypt the plaintext bytes using AES-256-CTR.
//! // note that the key size does not need to be explicitly stated.
//! let ciphertext = cipher.encrypt_ctr(&plaintext).expect("Counter overflow");
//! 
//! // decrypt the resultant ciphertext.
//! let decrypted_ct = cipher.decrypt_ctr(&ciphertext).expect("Counter overflow");
//! 
//! // round trip results in the same plaintext as the original message.
//! assert_eq!(plaintext, decrypted_ct);
//! ```
//! 

mod aes_lib;

pub use aes_lib::{Cipher, Error, Key, Result};
