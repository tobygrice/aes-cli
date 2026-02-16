#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::aesp::core::encrypt_block;
use crate::aesp::error::*;
use crate::aesp::modes::util::{ctr_block, xor_chunks};


/// Core counter encryption and decryption algorithm.
pub fn ctr_core(
    input: &[u8],
    round_keys: &[[u8; 16]],
    iv: &[u8; 12],
    ctr_start: u32,
) -> Result<Vec<u8>> {
    // check for counter overflow
    let num_blocks = u32::try_from((input.len() + 15) / 16).map_err(|_| Error::CounterOverflow)?;
    ctr_start
        .checked_add(num_blocks - 1)
        .ok_or(Error::CounterOverflow)?;

    // encrypt in parallel if feature enabled and size exceeds threshold
    #[cfg(feature = "parallel")]
    {      
        if input.len() > crate::aesp::modes::util::PARALLEL_THRESHOLD {
            let mut output = vec![0u8; input.len()];
            output
                .par_chunks_mut(16)
                .zip(input.par_chunks(16))
                .enumerate()
                .for_each(|(i, (out_chunk, in_chunk))| {
                    let ctr = ctr_start.wrapping_add(i as u32); // safe due to pre-check
                    let block = ctr_block(iv, ctr);
                    let keystream = encrypt_block(&block, round_keys);

                    // XOR only actual bytes (last chunk may be < 16)
                    for j in 0..in_chunk.len() {
                        out_chunk[j] = keystream[j] ^ in_chunk[j];
                    }
                });

            return Ok(output);
        }
    }

    // parallel feature not enabled or input len below threshold
    // encrypt serially

    // initialise ctr and output vector
    let mut ctr = ctr_start;
    let mut output = Vec::with_capacity(input.len());

    // for each chunk of input...
    for chunk in input.chunks(16) {
        let block = ctr_block(iv, ctr); // form block from iv + ctr
        // xor each element of input chunk (1-16 bytes) with encrypted ctr block
        let keystream = encrypt_block(&block, round_keys);
        let ct = xor_chunks(&keystream, chunk);
        output.extend_from_slice(&ct[..chunk.len()]);
        // increment ctr and throw error if overflow
        ctr = ctr.checked_add(1).ok_or(Error::CounterOverflow)?;
    }

    Ok(output)
}

#[cfg(test)]
mod test_ctr {
    use super::*;
    use crate::aesp::cipher::Cipher;
    use crate::aesp::key::Key;
    use crate::aesp::modes::util::test_util::{
        CTR_IV, CTR_START, KEY_128, KEY_192, KEY_256, PLAINTEXT, hex_to_bytes,
    };

    #[test]
    fn aes_ctr_128_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
        874d6191b620e3261bef6864990db6ce\
        9806f66b7970fdff8617187bb9fffdff\
        5ae4df3edbd5d35e5b4f09020db03eab\
        1e031dda2fbe03d1792170a0f3009cee",
        );

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);
        let encrypted = ctr_core(&PLAINTEXT, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ctr_128_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
        874d6191b620e3261bef6864990db6ce\
        9806f66b7970fdff8617187bb9fffdff\
        5ae4df3edbd5d35e5b4f09020db03eab\
        1e031dda2fbe03d1792170a0f3009cee",
        );

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);
        let decrypted = ctr_core(&ciphertext, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ctr_192_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
        1abc932417521ca24f2b0459fe7e6e0b\
        090339ec0aa6faefd5ccc2c6f4ce8e94\
        1e36b26bd1ebc670d1bd1d665620abf7\
        4f78a7f6d29809585a97daec58c6b050",
        );

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let encrypted = ctr_core(&PLAINTEXT, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ctr_192_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
        1abc932417521ca24f2b0459fe7e6e0b\
        090339ec0aa6faefd5ccc2c6f4ce8e94\
        1e36b26bd1ebc670d1bd1d665620abf7\
        4f78a7f6d29809585a97daec58c6b050",
        );

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let decrypted = ctr_core(&ciphertext, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ctr_256_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
        601ec313775789a5b7a7f504bbf3d228\
        f443e3ca4d62b59aca84e990cacaf5c5\
        2b0930daa23de94ce87017ba2d84988d\
        dfc9c58db67aada613c2dd08457941a6",
        );

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let encrypted = ctr_core(&PLAINTEXT, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ctr_256_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
        601ec313775789a5b7a7f504bbf3d228\
        f443e3ca4d62b59aca84e990cacaf5c5\
        2b0930daa23de94ce87017ba2d84988d\
        dfc9c58db67aada613c2dd08457941a6",
        );

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let decrypted = ctr_core(&ciphertext, cipher.get_round_keys(), &CTR_IV, CTR_START)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }
}
