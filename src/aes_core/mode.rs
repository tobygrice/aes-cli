use super::decryption::decrypt_block;
use super::encryption::encrypt_block;
use super::error::*;
use super::key::expand_key;
use super::util::{blockify, blockify_pad, ctr_block, unpad, xor_block};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    ModeECB,
    ModeCTR,
    ModeGCM,
}

pub(crate) fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let round_keys = expand_key(key)?;
    let plaintext = blockify_pad(plaintext);

    let mut ciphertext: Vec<u8> = Vec::with_capacity(plaintext.len() * 16);
    for block in plaintext {
        let enc_block = encrypt_block(&block, &round_keys);
        ciphertext.append(&mut enc_block.into_iter().flatten().collect());
    }

    Ok(ciphertext)
}

pub(crate) fn decrypt_ecb(ciphertext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let round_keys = expand_key(key)?;
    let ciphertext = blockify(ciphertext)?;

    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len() * 16);
    for block in ciphertext {
        let dec_block = decrypt_block(&block, &round_keys);
        plaintext.append(&mut dec_block.into_iter().flatten().collect());
    }

    unpad(&mut plaintext);
    Ok(plaintext)
}

pub(crate) fn ctr(input: &[u8], key: &[u8], iv: &[u8; 12], ctr_start: u32) -> Result<Vec<u8>> {
    let round_keys: Vec<[[u8; 4]; 4]> = expand_key(&key)?;
    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    let mut ctr = ctr_start; // mostly used for testing, in practice always start at 0

    for chunk in input.chunks(16) {
        let block = ctr_block(iv, ctr); // form block from iv + ctr
        // encrypt block
        let keystream = encrypt_block(&block, &round_keys);
        // xor each element of chunk (1-16 bytes) with corresponding elem in keystream
        output.extend_from_slice(&xor_block(keystream, chunk));
        ctr = match ctr.checked_add(1) {
            Some(c) => c,
            None => return Err(Error::CounterOverflow)
        };
    }

    Ok(output)
}


#[cfg(test)]
mod tests {
    use super::*;

    // all test vectors from NIST 800-38a
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf

    const PLAINTEXT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, //
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, //
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, //
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, //
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, //
    ];

    const KEY_128: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, //
    ];

    const KEY_192: [u8; 24] = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, //
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, //
    ];

    const KEY_256: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, //
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, //
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4, //
    ];

    const CTR_IV: [u8; 12] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    ];
    const CTR_START: u32 = 0xfcfdfeff;

    #[test]
    fn aes_ctr_128_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
        874d6191b620e3261bef6864990db6ce\
        9806f66b7970fdff8617187bb9fffdff\
        5ae4df3edbd5d35e5b4f09020db03eab\
        1e031dda2fbe03d1792170a0f3009cee",
        );

        let encrypted = ctr(&PLAINTEXT, &KEY_128, &CTR_IV, CTR_START)?;

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

        let decrypted = ctr(&ciphertext, &KEY_128, &CTR_IV, CTR_START)?;

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

        let encrypted = ctr(&PLAINTEXT, &KEY_192, &CTR_IV, CTR_START)?;

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

        let decrypted = ctr(&ciphertext, &KEY_192, &CTR_IV, CTR_START)?;

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

        let encrypted = ctr(&PLAINTEXT, &KEY_256, &CTR_IV, CTR_START)?;

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

        let decrypted = ctr(&ciphertext, &KEY_256, &CTR_IV, CTR_START)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_128_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
    3ad77bb40d7a3660a89ecaf32466ef97\
    f5d3d58503b9699de785895a96fdbaaf\
    43b1cd7f598ece23881b00e3ed030688\
    7b0c785e27e8ad3f8223207104725dd4\
    a254be88e037ddd9d79fb6411c3f9df8",
        );

        let encrypted = encrypt_ecb(&PLAINTEXT, &KEY_128)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_128_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    3ad77bb40d7a3660a89ecaf32466ef97\
    f5d3d58503b9699de785895a96fdbaaf\
    43b1cd7f598ece23881b00e3ed030688\
    7b0c785e27e8ad3f8223207104725dd4\
    a254be88e037ddd9d79fb6411c3f9df8",
        );

        let decrypted = decrypt_ecb(&ciphertext, &KEY_128)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_192_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
    bd334f1d6e45f25ff712a214571fa5cc\
    974104846d0ad3ad7734ecb3ecee4eef\
    ef7afd2270e2e60adce0ba2face6444e\
    9a4b41ba738d6c72fb16691603c18e0e\
    daa0af074bd8083c8a32d4fc563c55cc",
        );

        let encrypted = encrypt_ecb(&PLAINTEXT, &KEY_192)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_192_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    bd334f1d6e45f25ff712a214571fa5cc\
    974104846d0ad3ad7734ecb3ecee4eef\
    ef7afd2270e2e60adce0ba2face6444e\
    9a4b41ba738d6c72fb16691603c18e0e\
    daa0af074bd8083c8a32d4fc563c55cc",
        );

        let decrypted = decrypt_ecb(&ciphertext, &KEY_192)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_256_encrypt() -> Result<()> {
        let expected = hex_to_bytes(
            "
    f3eed1bdb5d2a03c064b5a7e3db181f8\
    591ccb10d410ed26dc5ba74a31362870\
    b6ed21b99ca6f4f9f153e7b1beafed1d\
    23304b7a39f9f3ff067d8d8f9e24ecc7\
    4c45dfb3b3b484ec35b0512dc8c1c4d6",
        );

        let encrypted = encrypt_ecb(&PLAINTEXT, &KEY_256)?;

        assert_eq!(
            expected, encrypted,
            "encypted result does not match expected"
        );
        Ok(())
    }

    #[test]
    fn aes_ecb_256_decrypt() -> Result<()> {
        let ciphertext = hex_to_bytes(
            "
    f3eed1bdb5d2a03c064b5a7e3db181f8\
    591ccb10d410ed26dc5ba74a31362870\
    b6ed21b99ca6f4f9f153e7b1beafed1d\
    23304b7a39f9f3ff067d8d8f9e24ecc7\
    4c45dfb3b3b484ec35b0512dc8c1c4d6",
        );

        let decrypted = decrypt_ecb(&ciphertext, &KEY_256)?;

        assert_eq!(
            PLAINTEXT.to_vec(),
            decrypted,
            "decrypted result does not match expected"
        );
        Ok(())
    }

    // hex_to_bytes written by an LLM
    fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
