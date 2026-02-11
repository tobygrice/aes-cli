use super::decryption::decrypt_block;
use super::encryption::encrypt_block;
use super::error::*;
use super::key::expand_key;
use super::util::{blockify, blockify_pad, ctr_block, flatten_block, gf_mul, unpad, xor_chunks};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Mode {
    ModeECB,
    ModeCTR,
    ModeGCM,
}

pub(crate) fn encrypt_ecb(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let round_keys = expand_key(key)?;
    let plaintext = blockify_pad(plaintext, true);

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
    let round_keys = expand_key(&key)?;
    let mut output = Vec::with_capacity(input.len());
    let mut ctr = ctr_start; // mostly used for testing, in practice always start at 0

    for chunk in input.chunks(16) {
        let block = ctr_block(iv, ctr); // form block from iv + ctr
        // encrypt block
        // xor each element of chunk (1-16 bytes) with corresponding elem in keystream
        let keystream = flatten_block(encrypt_block(&block, &round_keys));
        let ct = xor_chunks(&keystream, chunk);
        output.extend_from_slice(&ct[..chunk.len()]);
        ctr = match ctr.checked_add(1) {
            Some(c) => c,
            None => return Err(Error::CounterOverflow),
        };
    }

    Ok(output)
}

/*
https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf
diagram on page 5

H = 128 0s encrypted with key
start with accumulator s = 0
for each 16-byte block b:
    s = (s ^ b) * H (GF128 multiplication)

where blocks are:
    - all AAD blocks (padded)
    - all ciphertext blocks (padded)
    - one block containing aad.len + ct.len

final tag = s ^ encrypt_block(J0, key)

where J0 is:
    - IV || 1u32 (initial ctr block for ctr = 1)
*/
pub(crate) fn compute_tag(ciphertext: &[u8], key: &[u8], iv: &[u8; 12], aad: &[u8]) -> Result<[u8; 16]> {
    let round_keys = expand_key(key)?;

    // create inital ctr block (xor'd with tag at end)
    let j0 = ctr_block(iv, 1);
    let j0_e = flatten_block(encrypt_block(&j0, &round_keys));

    // generate H by encrypting block of 0s
    let h = flatten_block(encrypt_block(&[[0u8; 4]; 4], &round_keys));

    // s = ghash accumulator
    let mut s = [0u8; 16];

    // compute s over AAD
    for aad_chunk in aad.chunks(16) {
        s = gf_mul(xor_chunks(&s, aad_chunk), h);
    }

    // compute s over ciphertext
    for ct_chunk in ciphertext.chunks(16) {
        s = gf_mul(xor_chunks(&s, ct_chunk), h);
    }

    // authenticate message length, build aad_bits || ct_bits
    let aad_bits = (aad.len() as u64) * 8;
    let ct_bits = (ciphertext.len() as u64) * 8;
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len[8..].copy_from_slice(&ct_bits.to_be_bytes());

    s = gf_mul(xor_chunks(&s, &len), h);

    // tag = E(K, J0) ^ S
    Ok(xor_chunks(&s, &j0_e))
}


#[cfg(test)]
mod test_ecb_ctr {
    use super::*;

    // all test vectors from
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

    pub(super) fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}

// gcm tests written with LLM assistance
#[cfg(test)]
mod test_gcm {
    use super::*;
    use super::test_ecb_ctr::hex_to_bytes;

    // all test vectors from
    // https://boringssl.googlesource.com/boringssl.git/%2B/734fca08902889c88e84839134262bdf5c12eebf/crypto/cipher/cipher_test.txt

    #[test]
    fn tag_no_pt_no_aad() {
        // Vector:
        // key = 00..00 (16 bytes)
        // iv  = 00..00 (12 bytes)
        // aad = empty
        // ct  = empty
        // tag = 58e2fccefa7e3061367f1d57a4e7455a
        let key = hex_to_bytes("00000000000000000000000000000000");
        let iv = hex_to_arr_12("000000000000000000000000");
        let aad: [u8; 0] = [];
        let ciphertext: [u8; 0] = [];

        let tag = compute_tag(&ciphertext, &key, &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("58e2fccefa7e3061367f1d57a4e7455a"));
    }

    #[test]
    fn tag_no_aad_1() {
        // Vector:
        // key = 00..00 (16 bytes)
        // iv  = 00..00 (12 bytes)
        // pt  = 00..00 (16 bytes)
        // ct  = 0388dace60b6a392f328c2b971b2fe78
        // aad = empty
        // tag = ab6e47d42cec13bdf53a67b21257bddf
        let key = hex_to_bytes("00000000000000000000000000000000");
        let iv = hex_to_arr_12("000000000000000000000000");
        let aad: [u8; 0] = [];
        let ciphertext = hex_to_bytes("0388dace60b6a392f328c2b971b2fe78");

        let tag = compute_tag(&ciphertext, &key, &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    #[test]
    fn tag_no_aad_2() {
        // Vector:
        // key = feffe9928665731c6d6a8f9467308308
        // iv  = cafebabefacedbaddecaf888
        // aad = empty
        // ct  = 42831e...3f5985
        // tag = 4d5c2af327cd64a62cf35abd2ba6fab4
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_arr_12("cafebabefacedbaddecaf888");
        let aad: [u8; 0] = [];
        let ciphertext = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091473f5985",
        );

        let tag = compute_tag(&ciphertext, &key, &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("4d5c2af327cd64a62cf35abd2ba6fab4"));
    }

    #[test]
    fn tag_with_aad() {
        // Vector:
        // key = feffe9928665731c6d6a8f9467308308
        // iv  = cafebabefacedbaddecaf888
        // aad = feedfacedeadbeeffeedfacedeadbeefabaddad2
        // ct  = 42831e...58e091
        // tag = 5bc94fbc3221a5db94fae95ae7121a47
        let key = hex_to_bytes("feffe9928665731c6d6a8f9467308308");
        let iv = hex_to_arr_12("cafebabefacedbaddecaf888");
        let aad = hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let ciphertext = hex_to_bytes(
            "42831ec2217774244b7221b784d0d49c\
             e3aa212f2c02a4e035c17e2329aca12e\
             21d514b25466931c7d8f6a5aac84aa05\
             1ba30b396a0aac973d58e091",
        );

        let tag = compute_tag(&ciphertext, &key, &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("5bc94fbc3221a5db94fae95ae7121a47"));
    }

    fn hex_to_arr_12(hex: &str) -> [u8; 12] {
        let v = hex_to_bytes(hex);
        assert_eq!(v.len(), 12);
        let mut out = [0u8; 12];
        out.copy_from_slice(&v);
        out
    }

    fn hex_to_arr_16(hex: &str) -> [u8; 16] {
        let v = hex_to_bytes(hex);
        assert_eq!(v.len(), 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        out
    }
}
