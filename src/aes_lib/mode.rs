use crate::aes_lib::core::{decrypt_block, encrypt_block};
use crate::aes_lib::error::*;
use crate::aes_lib::util::{ctr_block, gf_mul, xor_chunks};

/// Core ECB encryption algorithm. Encrypts plaintext in 16-byte blocks to form ciphertext. Uses PKCS#7 padding.
pub(crate) fn encrypt_ecb_core(plaintext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    // last block needs to be PKCS#7 padded. Variables to track when to start padding:
    let rem_len = plaintext.len() % 16; // number of leftover bytes after chunking into 16
    let pad_len = 16 - rem_len; // number of bytes to be padded
    let chunks_len = plaintext.len() - rem_len; // number of bytes that can fit into 16-byte chunks

    let mut ciphertext = vec![0u8; plaintext.len() + pad_len];

    // encrypt plaintext in 16-byte blocks
    for (pt, ct) in plaintext[..chunks_len]
        .chunks_exact(16)
        .zip(ciphertext[..chunks_len].chunks_exact_mut(16))
    {
        let pt_block: &[u8; 16] = pt.try_into().unwrap(); // safe unwrap, loop guarantees exact chunks 16
        let enc = encrypt_block(pt_block, round_keys);
        ct.copy_from_slice(&enc);
    }

    // PKCS#7 pad final block
    let mut last = [0u8; 16];
    last[..rem_len].copy_from_slice(&plaintext[chunks_len..]); // rem may be 0 (copies nothing)
    last[rem_len..].fill(pad_len as u8);

    // encrypt and write final padded block
    let enc_last = encrypt_block(&last, round_keys);
    ciphertext[chunks_len..].copy_from_slice(&enc_last);

    Ok(ciphertext)
}

/// Core ECB decryption algorithm. Decrypts plaintext in 16-byte blocks to form plaintext. Assumes plaintext was PKCS#7 padded.
pub(crate) fn decrypt_ecb_core(ciphertext: &[u8], round_keys: &[[u8; 16]]) -> Result<Vec<u8>> {
    // ECB ciphertext should (and must) always be a multiple of 16 bytes.
    if ciphertext.len() % 16 != 0 {
        return Err(Error::InvalidCiphertext {
            len: ciphertext.len(),
            context: "ECB ciphertext not a multiple of 16 bytes",
        });
    }

    let mut plaintext = vec![0u8; ciphertext.len()];

    // decrypt ciphertext in 16-byte blocks
    for (ct, pt) in ciphertext
        .chunks_exact(16)
        .zip(plaintext.chunks_exact_mut(16))
    {
        let ct_block: &[u8; 16] = ct.try_into().unwrap(); // safe unwrap, loop guarantees exact chunks 16
        let dec = decrypt_block(ct_block, round_keys);
        pt.copy_from_slice(&dec);
    }

    // unpad plaintext
    let pad_len: usize = match plaintext.last() {
        Some(v) => *v as usize,
        None => 0,
    };
    plaintext.truncate(plaintext.len() - pad_len);

    Ok(plaintext)
}

/// Core counter encryption and decryption algorithm (CTR is symettric)
pub(crate) fn ctr_core(
    input: &[u8],
    round_keys: &[[u8; 16]],
    iv: &[u8; 12],
    ctr_start: u32,
) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(input.len());
    let mut ctr = ctr_start;

    // for each chunk of input...
    for chunk in input.chunks(16) {
        let block = ctr_block(iv, ctr); // form block from iv + ctr
        // xor each element of input chunk (1-16 bytes) with encrypted ctr block
        let keystream = encrypt_block(&block, round_keys);
        let ct = xor_chunks(&keystream, chunk);
        output.extend_from_slice(&ct[..chunk.len()]);
        // increment ctr and throw error if overflow
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

H = block of 0s encrypted with key
start with accumulator s = 0
for each 16-byte block b:
    s = (s ^ b) * H (GF128 multiplication)

where blocks are:
    - all AAD blocks (padded)
    - all ciphertext blocks (padded)
    - one block comprised aad.len || ct.len

final tag = s ^ encrypt_block(J0, key)

where J0 is:
    - IV || 1u32 (initial ctr block for ctr = 1)
*/
/// Function to compute GCM cryptographic tag from ciphertext + AAD
pub(crate) fn compute_tag(
    ciphertext: &[u8],
    round_keys: &[[u8; 16]],
    iv: &[u8; 12],
    aad: &[u8],
) -> Result<[u8; 16]> {
    // create initial ctr block (xor'd with tag at end)
    let j0 = ctr_block(iv, 1);
    let j0_e = encrypt_block(&j0, round_keys);

    // generate H by encrypting block of 0s
    let h = encrypt_block(&[0u8; 16], round_keys);

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

    // authenticate message length, build aad_size || ct_size
    let aad_size = (aad.len() as u64) * 8; // size in bits
    let ct_size = (ciphertext.len() as u64) * 8; // size in bits
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&aad_size.to_be_bytes());
    len[8..].copy_from_slice(&ct_size.to_be_bytes());

    s = gf_mul(xor_chunks(&s, &len), h);

    // tag = E(K, J0) ^ S
    Ok(xor_chunks(&s, &j0_e))
}

#[cfg(test)]
mod test_ecb_ctr {
    use super::*;
    use crate::aes_lib::cipher::Cipher;
    use crate::aes_lib::key::Key;

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

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);
        let encrypted = encrypt_ecb_core(&PLAINTEXT, cipher.get_round_keys())?;

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

        let key = Key::try_from_slice(&KEY_128)?;
        let cipher = Cipher::new(&key);
        let decrypted = decrypt_ecb_core(&ciphertext, cipher.get_round_keys())?;

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

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let encrypted = encrypt_ecb_core(&PLAINTEXT, cipher.get_round_keys())?;

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

        let key = Key::try_from_slice(&KEY_192)?;
        let cipher = Cipher::new(&key);
        let decrypted = decrypt_ecb_core(&ciphertext, cipher.get_round_keys())?;

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

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let encrypted = encrypt_ecb_core(&PLAINTEXT, cipher.get_round_keys())?;

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

        let key = Key::try_from_slice(&KEY_256)?;
        let cipher = Cipher::new(&key);
        let decrypted = decrypt_ecb_core(&ciphertext, cipher.get_round_keys())?;

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
    use super::test_ecb_ctr::hex_to_bytes;
    use super::*;
    use crate::aes_lib::cipher::Cipher;
    use crate::aes_lib::key::Key;

    // all test vectors from
    // https://boringssl.googlesource.com/boringssl.git/%2B/734fca08902889c88e84839134262bdf5c12eebf/crypto/cipher/cipher_test.txt

    #[test]
    fn tag_no_pt_no_aad() -> Result<()> {
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

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("58e2fccefa7e3061367f1d57a4e7455a"));

        Ok(())
    }

    #[test]
    fn tag_no_aad_1() -> Result<()> {
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

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("ab6e47d42cec13bdf53a67b21257bddf"));

        Ok(())
    }

    #[test]
    fn tag_no_aad_2() -> Result<()> {
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

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("4d5c2af327cd64a62cf35abd2ba6fab4"));

        Ok(())
    }

    #[test]
    fn tag_with_aad() -> Result<()> {
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

        let key = Key::try_from_slice(&key)?;
        let cipher = Cipher::new(&key);
        let tag = compute_tag(&ciphertext, cipher.get_round_keys(), &iv, &aad).unwrap();
        assert_eq!(tag, hex_to_arr_16("5bc94fbc3221a5db94fae95ae7121a47"));

        Ok(())
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
