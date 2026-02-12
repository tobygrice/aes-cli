mod args;

use aes::Key;
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
    Aes(#[from] aes::Error),
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
                    args::KeySize::Bits128 => aes::Key::rand_key_128()?,
                    args::KeySize::Bits192 => aes::Key::rand_key_192()?,
                    args::KeySize::Bits256 => aes::Key::rand_key_256()?,
                };
                fs::write(key_path, &rand_key.as_bytes())?;
                rand_key
            } else {
                // read key from key_path
                let key_bytes = fs::read(key_path)?;
                aes::Key::try_from_slice(&key_bytes)?
            };

            let cipher = aes::Cipher::new(&key);

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
                args::Mode::ModeECB => cipher.encrypt_ecb(&plaintext)?,
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
            let key = Key::try_from_slice(&key_bytes)?;

            let cipher = aes::Cipher::new(&key);

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
