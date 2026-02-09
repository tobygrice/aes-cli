use super::constants::SBOX_INV;
use super::key::add_round_key;
use super::util::dbl;

#[inline(always)]
pub(crate) fn decrypt_block(plaintext: &[[u8; 4]; 4], round_keys: &[[[u8; 4]; 4]]) -> [[u8; 4]; 4] {
    let mut state = plaintext.clone();
    let num_rounds = round_keys.len();

    add_round_key(&mut state, &round_keys.last().unwrap());

    for round_key in round_keys[1..num_rounds - 1].iter().rev() {
        shift_rows_inv(&mut state);
        sub_bytes_inv(&mut state);
        add_round_key(&mut state, round_key);
        mix_columns_inv(&mut state);
    }

    shift_rows_inv(&mut state);
    sub_bytes_inv(&mut state);
    add_round_key(&mut state, &round_keys[0]);

    state
}

#[inline(always)]
fn sub_bytes_inv(state: &mut [[u8; 4]; 4]) {
    for word in state {
        for byte in word {
            *byte = SBOX_INV[*byte as usize];
        }
    }
}

#[inline(always)]
fn shift_rows_inv(state: &mut [[u8; 4]; 4]) {
    let s = *state;
    *state = [
        [s[0][0], s[3][1], s[2][2], s[1][3]],
        [s[1][0], s[0][1], s[3][2], s[2][3]],
        [s[2][0], s[1][1], s[0][2], s[3][3]],
        [s[3][0], s[2][1], s[1][2], s[0][3]],
    ];
}

// optimisation by https://crypto.stackexchange.com/a/71206
#[inline(always)]
fn mix_columns_inv(state: &mut [[u8; 4]; 4]) {
    for word in state {
        let (a, b, c, d) = (word[0], word[1], word[2], word[3]);
        let x = dbl(a ^ b ^ c ^ d);
        let y = dbl(x ^ a ^ c);
        let z = dbl(x ^ b ^ d);
        word[0] = dbl(y ^ a ^ b) ^ b ^ c ^ d; /* 14a + 11b + 13c + 9d */
        word[1] = dbl(z ^ b ^ c) ^ c ^ d ^ a; /* 14b + 11c + 13d + 9a */
        word[2] = dbl(y ^ c ^ d) ^ d ^ a ^ b; /* 14c + 11d + 13a + 9b */
        word[3] = dbl(z ^ d ^ a) ^ a ^ b ^ c; /* 14d + 11a + 13b + 9c */
    }
}

#[cfg(test)]
mod tests {
    use crate::aes_core::error::Result;
    use crate::aes_core::key::expand_key;
    use crate::aes_core::{decryption, encryption};

    #[test]
    fn test_shift_rows() {
        let mut actual: [[u8; 4]; 4] = [
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b],
            [0x0c, 0x0d, 0x0e, 0x0f],
        ];
        let expected = actual;

        encryption::shift_rows(&mut actual);
        decryption::shift_rows_inv(&mut actual);

        assert_eq!(
            actual, expected,
            "shift rows inverse does not exactly reverse shift rows"
        )
    }

    #[test]
    fn test_sub_bytes() {
        let mut actual: [[u8; 4]; 4] = [
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b],
            [0x0c, 0x0d, 0x0e, 0x0f],
        ];
        let expected = actual;

        encryption::sub_bytes(&mut actual);
        decryption::sub_bytes_inv(&mut actual);

        assert_eq!(
            actual, expected,
            "sub bytes inverse does not exactly reverse sub bytes"
        )
    }

    #[test]
    fn test_mix_columns() {
        let mut actual: [[u8; 4]; 4] = [
            [0x00, 0x01, 0x02, 0x03],
            [0x04, 0x05, 0x06, 0x07],
            [0x08, 0x09, 0x0a, 0x0b],
            [0x0c, 0x0d, 0x0e, 0x0f],
        ];
        let expected = actual;

        encryption::mix_columns(&mut actual);
        decryption::mix_columns_inv(&mut actual);

        assert_eq!(
            actual, expected,
            "mix columns inverse does not exactly reverse mix columns"
        )
    }

    #[test]
    fn test_decrypt_block() -> Result<()> {
        let key: [u8; 32] = [
            0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, //
            0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, //
            0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, //
            0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4, //
        ];
        let plaintext: [[u8; 4]; 4] = [
            [0x6B, 0xC1, 0xBE, 0xE2],
            [0x2E, 0x40, 0x9F, 0x96],
            [0xE9, 0x3D, 0x7E, 0x11],
            [0x73, 0x93, 0x17, 0x2A],
        ];

        let round_keys = expand_key(&key)?;
        let encrypted = encryption::encrypt_block(&plaintext, &round_keys);
        let decrypted = decryption::decrypt_block(&encrypted, &round_keys);

        assert_eq!(
            decrypted, plaintext,
            "decrypt block does not exactly reverse encrypt block"
        );

        Ok(())
    }
}
