use crate::aesp::error::*;

pub const PARALLEL_THRESHOLD: usize = 4 * 1024; // encrypt in parallel if input size gt 4 KiB
const GHASH_R: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000; // reduction constant for GHASH

#[inline(always)]
pub(crate) fn ctr_block(iv: &[u8; 12], ctr: u32) -> [u8; 16] {
    let cb = ctr.to_be_bytes();
    [
        iv[00], iv[01], iv[02], iv[03], iv[04], iv[05], iv[06], iv[07], iv[08], iv[09], iv[10],
        iv[11], cb[00], cb[01], cb[02], cb[03],
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
pub(crate) fn mul_x(v: u128) -> u128 {
    // Multiply by x (in the GHASH field representation)
    let lsb = v & 1;
    let mut v2 = v >> 1;
    v2 ^= GHASH_R & (0u128.wrapping_sub(lsb));
    v2
}

#[inline(always)]
pub(crate) fn mul_x4(mut v: u128) -> u128 {
    // Multiply by x^4 (4 successive mul_x)
    v = mul_x(v);
    v = mul_x(v);
    v = mul_x(v);
    v = mul_x(v);
    v
}

#[inline(always)]
pub(crate) fn unpad(input: &mut Vec<u8>) -> Result<()> {
    if input.is_empty() {
        return Err(Error::InvalidCiphertext {
            len: 0,
            context: "Unpad: attempted to unpad empty input",
        });
    }

    let pad = *input.last().unwrap() as usize;
    if pad == 0 || pad > 16 || pad > input.len() {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "Unpad: invalid padding length specified by last byte",
        });
    }

    let start = input.len() - pad;
    if !input[start..].iter().all(|&b| b as usize == pad) {
        return Err(Error::InvalidCiphertext {
            len: input.len(),
            context: "Unpad: invalid PKCS#7 padding format",
        });
    }

    input.truncate(start);
    Ok(())
}

#[cfg(test)]
pub(crate) mod test_util {
    pub fn hex_to_bytes(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0, "hex string must have even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    pub fn hex_to_arr_12(hex: &str) -> [u8; 12] {
        let v = hex_to_bytes(hex);
        assert_eq!(v.len(), 12);
        let mut out = [0u8; 12];
        out.copy_from_slice(&v);
        out
    }

    pub fn hex_to_arr_16(hex: &str) -> [u8; 16] {
        let v = hex_to_bytes(hex);
        assert_eq!(v.len(), 16);
        let mut out = [0u8; 16];
        out.copy_from_slice(&v);
        out
    }

    // all test vectors from
    // https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    pub const PLAINTEXT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, //
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a, //
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, //
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51, //
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, //
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, //
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, //
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10, //
    ];

    pub const KEY_128: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, //
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c, //
    ];

    pub const KEY_192: [u8; 24] = [
        0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, //
        0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, //
        0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, //
    ];

    pub const KEY_256: [u8; 32] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, //
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, //
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, //
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4, //
    ];

    pub const CTR_IV: [u8; 12] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
    ];
    pub const CTR_START: u32 = 0xfcfdfeff;
}
