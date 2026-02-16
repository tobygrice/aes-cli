use rand::TryRngCore;
use rand::rngs::OsRng;

use crate::aes_lib::error::Result;

pub(crate) fn random_iv() -> Result<[u8; 12]> {
    let mut iv = [0u8; 12];
    OsRng.try_fill_bytes(&mut iv)?;
    Ok(iv)
}

#[inline(always)]
pub(crate) fn ctr_block(iv: &[u8; 12], ctr: u32) -> [u8; 16] {
    let cb = ctr.to_be_bytes();
    [
        iv[00], iv[01], iv[02], iv[03],
        iv[04], iv[05], iv[06], iv[07],
        iv[08], iv[09], iv[10], iv[11],
        cb[00], cb[01], cb[02], cb[03],
    ]
}


#[inline(always)]
pub(crate) fn xor_chunks(y: &[u8; 16], chunk: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = *y;
    for i in 0..chunk.len() {
        out[i] ^= chunk[i];
    }
    out
}

#[inline(always)]
pub(crate) fn xor_words(a: &[u8; 4], b: &[u8; 4]) -> [u8; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

// gf_mul written with LLM assistance
#[inline(always)]
pub(crate) fn gf_mul(tag: [u8; 16], h: [u8; 16]) -> [u8; 16] {
    const R: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000;

    let x = u128::from_be_bytes(tag);
    let mut v = u128::from_be_bytes(h);
    let mut z: u128 = 0;

    // Process x bits from MSB -> LSB
    for i in 0..128 {
        let bit = (x >> (127 - i)) & 1;
        // If bit == 1, z ^= v (branchless)
        z ^= v & (0u128.wrapping_sub(bit));

        // v = v >> 1; if LSB was 1, v ^= R
        let lsb = v & 1;
        v >>= 1;
        v ^= R & (0u128.wrapping_sub(lsb));
    }

    z.to_be_bytes()
}
