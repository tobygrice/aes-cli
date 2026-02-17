mod args;

use args::{Cli, Commands};
use clap::Parser;

use std::fs;
use std::time::Instant;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("--aad is only valid with --mode gcm")]
    AadInvalidMode,

    #[error("invalid --aad hex: {0}")]
    AadInvalidHex(#[from] std::num::ParseIntError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Aes(#[from] aesp::Error),
}

fn main() {
    if let Err(e) = aes_cli() {
        eprintln!("error: {e}");
    }
}

fn aes_cli() -> Result<(), CliError> {
    let args = Cli::parse();

    match args.command {
        Commands::Encrypt(enc) => {
            // common args:
            let input_path = enc.common.input; // move ownership
            let output_path = enc.common.output;
            let key_path = enc.common.key;
            let mode = enc.common.mode;

            // read plaintext from input_path
            let plaintext = fs::read(input_path)?;

            // read or generate key
            let key = if enc.gen_key {
                let rand_key = match enc.key_size {
                    args::KeySize::Bits128 => aesp::Key::rand_key_128()?,
                    args::KeySize::Bits192 => aesp::Key::rand_key_192()?,
                    args::KeySize::Bits256 => aesp::Key::rand_key_256()?,
                };
                fs::write(key_path, &rand_key.as_bytes())?;
                rand_key
            } else {
                // read key from key_path
                let key_bytes = fs::read(key_path)?;
                aesp::Key::try_from_slice(&key_bytes)?
            };

            let cipher = aesp::Cipher::new(&key);

            // parse AAD
            let aad: Option<Vec<u8>> = match enc.aad {
                Some(aad_str) => {
                    if mode != args::Mode::ModeGCM {
                        return Err(CliError::AadInvalidMode);
                    }
                    Some(parse_aad(&aad_str)?)
                }
                None => None,
            };

            let start = Instant::now();

            // encrypt plaintext and write output
            let ciphertext = match mode {
                args::Mode::ModeECB => cipher.encrypt_ecb(&plaintext),
                args::Mode::ModeCTR => cipher.encrypt_ctr(&plaintext)?,
                args::Mode::ModeGCM => cipher.encrypt_gcm(&plaintext, aad.as_deref())?,
            };

            let duration = start.elapsed();

            fs::write(output_path, &ciphertext)?;
            println!(
                "Encrypted {} bytes in {} ms",
                plaintext.len(),
                duration.as_millis()
            );
            Ok(())
        }
        Commands::Decrypt(common) => {
            let input_path = common.input; // move ownership
            let output_path = common.output;
            let key_path = common.key;
            let mode = common.mode;

            // read inputs
            let ciphertext = fs::read(input_path)?;
            let key_bytes = fs::read(key_path)?;
            let key = aesp::Key::try_from_slice(&key_bytes)?;

            let cipher = aesp::Cipher::new(&key);

            let start = Instant::now();

            // decrypt ciphertext and write output
            let (plaintext, aad) = match mode {
                args::Mode::ModeECB => (cipher.decrypt_ecb(&ciphertext)?, None),
                args::Mode::ModeCTR => (cipher.decrypt_ctr(&ciphertext)?, None),
                args::Mode::ModeGCM => cipher.decrypt_gcm(&ciphertext)?,
            };

            let duration = start.elapsed();

            fs::write(output_path, &plaintext)?;

            match aad {
                Some(aad) => {
                    print!("AAD = ");
                    for b in &aad {
                        print!("{:02x}", b);
                    }
                    println!();
                }
                None => {}
            }

            println!(
                "Decrypted {} bytes in {} ms",
                plaintext.len(),
                duration.as_millis()
            );

            Ok(())
        }
    }
}

// parse_aad written with LLM assistance:
fn parse_aad(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    let mut hex: String = s.chars().filter(|c| !c.is_whitespace()).collect();

    if hex.len() % 2 == 1 {
        hex.insert(0, '0');
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
}

#[cfg(test)]
mod test {
    #[test]
    fn readme_sample_test() {
        use aesp::{Cipher, Key};

        // generate a random 256-bit key.
        let key = Key::rand_key_256().expect("Random key generation failed");

        // instantiate a cipher object using that key.
        let cipher = Cipher::new(&key);

        // instantiate sample plaintext (cipher encrypts raw bytes).
        let plaintext = ("Hello, World!").as_bytes();

        // encrypt the plaintext bytes using AES-256-CTR.
        // note that the key size does not need to be explicitly stated.
        let ciphertext = cipher.encrypt_ctr(plaintext).expect("Counter overflow");

        // decrypt the resultant ciphertext.
        let decrypted_ct = cipher.decrypt_ctr(&ciphertext).expect("Counter overflow");

        // round trip results in the same plaintext as the original message.
        assert_eq!(plaintext, decrypted_ct);

        // for ECB mode:
        let ecb_ciphertext = cipher.encrypt_ecb(plaintext);
        let ecb_plaintext = cipher
            .decrypt_ecb(&ecb_ciphertext)
            .expect("Invalid ciphertext");
        assert_eq!(plaintext, ecb_plaintext);

        // for GCM with AAD:
        let aad = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let gcm_ciphertext = cipher
            .encrypt_gcm(plaintext, Some(&aad))
            .expect("Counter overflow");

        // decrypt GCM returns a tuple containing (plaintext, Option(aad))
        let (gcm_plaintext, res_aad) = cipher
            .decrypt_gcm(&gcm_ciphertext)
            .expect("Invalid tag or counter overflow");
        assert_eq!(plaintext, gcm_plaintext);
        assert_eq!(Some(aad), res_aad);
    }
}
