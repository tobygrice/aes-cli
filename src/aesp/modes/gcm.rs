use crate::aesp::core::encrypt_block;
use crate::aesp::error::*;
use crate::aesp::modes::util::{ctr_block, mul_x, mul_x4, xor_chunks};

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
pub fn compute_tag(
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

    // precompute GHASH tables for H
    let gkey = GHashKey::new(h);

    // s = ghash accumulator
    let mut s = [0u8; 16];

    // compute s over AAD (zero-pads final partial block)
    gkey.ghash_update(&mut s, aad);

    // compute s over ciphertext (zero-pads final partial block)
    gkey.ghash_update(&mut s, ciphertext);

    // authenticate message length, build aad_size || ct_size
    let aad_size = (aad.len() as u64) * 8; // size in bits
    let ct_size = (ciphertext.len() as u64) * 8; // size in bits
    let mut len = [0u8; 16];
    len[..8].copy_from_slice(&aad_size.to_be_bytes());
    len[8..].copy_from_slice(&ct_size.to_be_bytes());

    // s = (s xor len) * H
    for i in 0..16 {
        s[i] ^= len[i];
    }
    s = gkey.mul(s);

    // tag = E(K, J0) ^ S
    Ok(xor_chunks(&s, &j0_e))
}


/// Precomputed tables for fast GHASH multiplication by fixed H. This struct written with LLM assistance.
struct GHashKey {
    // 32 nibbles across 16 bytes, each nibble 0..15 contributes a u128
    table: [[u128; 16]; 32],
}

impl GHashKey {
    /// Build the precomputed nibble tables for this H
    fn new(h: [u8; 16]) -> Self {
        let mut table = [[0u128; 16]; 32];

        // v_pos corresponds to the v value at the start of this nibble position
        // (i.e., after shifting for all earlier bits)
        let mut v_pos = u128::from_be_bytes(h);

        for pos in 0..32 {
            for nib in 0..16u8 {
                let mut acc = 0u128;
                let mut v = v_pos;

                // Consume nibble bits MSB -> LSB
                for k in 0..4 {
                    let bit = (nib >> (3 - k)) & 1;
                    acc ^= v & (0u128.wrapping_sub(bit as u128));
                    v = mul_x(v);
                }

                table[pos][nib as usize] = acc;
            }

            // Advance v_pos by 4 bits for next nibble position
            v_pos = mul_x4(v_pos);
        }

        Self { table }
    }

    /// Update GHASH accumulator `s` with arbitrary-length data (AAD or ciphertext).
    #[inline(always)]
    fn ghash_update(&self, s: &mut [u8; 16], data: &[u8]) {
        for chunk in data.chunks(16) {
            for i in 0..chunk.len() {
                s[i] ^= chunk[i];
            }
            *s = self.mul(*s);
        }
    }

    /// Compute x * H (GHASH field multiply) using the precomputed table.
    #[inline(always)]
    fn mul(&self, x: [u8; 16]) -> [u8; 16] {
        let mut z = 0u128;
        let mut pos = 0usize;

        // process bytes 0..15, high nibble then low nibble (MSB -> LSB)
        for &b in x.iter() {
            z ^= self.table[pos][(b >> 4) as usize];
            pos += 1;
            z ^= self.table[pos][(b & 0x0F) as usize];
            pos += 1;
        }

        z.to_be_bytes()
    }
}


// gcm tests written with LLM assistance
#[cfg(test)]
mod test_gcm {
    use super::*;
    use crate::aesp::cipher::Cipher;
    use crate::aesp::key::Key;
    use crate::aesp::modes::util::test_util::{hex_to_arr_12, hex_to_arr_16, hex_to_bytes};

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
}
