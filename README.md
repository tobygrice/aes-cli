# AES Parallelised

## About

An AES library targeting performance through parallelism.

Supported modes are ECB, CTR, and GCM. A CLI binary is also available as an optional feature.

Library documentation is available on [docs.rs](https://docs.rs/aesp).

This is a personal project, not intended for production -- use at your own risk!

## CLI Usage

The CLI tool can installed using `cargo`:

```bash
cargo install aesp --features cli
```

If you would prefer not to use `cargo`, you can download the binaries from the [releases page](https://github.com/tobygrice/aesp/releases) on GitHub.

Once installed, usage is simple:

```bash
aesp encrypt -i plaintext.txt -o ciphertext -k keyfile --gen-key
aesp decrypt -i ciphertext -o decrypted.txt -k keyfile
```

The `help` command prints the following:

```plaintext
Usage: aesp <COMMAND>

Commands:
  encrypt  Encrypt input to output
  decrypt  Decrypt input to output
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Encryption

Encryption usage is as follows:

```plaintext
Encrypt input to output

Usage: aesp encrypt [OPTIONS] --input <INPUT> --output <OUTPUT> --key <KEY>

Options:
  -m, --mode <MODE>          Mode of operation [default: gcm] [possible values: ecb, ctr, gcm]
  -i, --input <INPUT>        Input file path
  -o, --output <OUTPUT>      Output file path
  -k, --key <KEY>            Key file path
      --gen-key              Generate a random key (written to path specified by key)
      --key-size <KEY_SIZE>  Only valid with --gen-key [default: 256] [possible values: 128, 192, 256]
      --aad <HEX>            Additional authenticated data, provided as hex string (optional, GCM only)
  -h, --help                 Print help
```

### Decryption

Decryption usage is as follows:

```plaintext
Decrypt input to output

Usage: aesp decrypt --input <INPUT> --output <OUTPUT> --key <KEY>

Options:
  -i, --input <INPUT>    Input file path
  -o, --output <OUTPUT>  Output file path
  -k, --key <KEY>        Key file path
  -h, --help             Print help
```

## Library Usage

The API exports two structs:

- `AesKey` - stores key bytes, used to instantiate an `AesCipher`
- `AesCipher` - stores round keys and provides encryption/decryption functions

A `Result` type containing an `AesError` is also exported, which is returned by most encryption/decryption functions.

### Examples

```rust
use aesp::{Key, Cipher};

// generate a random 256-bit key. Also available: try_from_slice, rand_key_128, and rand_key_192.
let key = Key::rand_key_256()?;

// instantiate a cipher object using that key.
let cipher = Cipher::new(&key);

// sample plaintext (cipher encrypts raw bytes).
let plaintext = ("Hello, World!").as_bytes();

// encrypt the plaintext bytes using AES-256-CTR.
// note that the key size does not need to be explicitly stated.
let ctr_ciphertext = cipher.encrypt_ctr(plaintext)?;

// decrypt the resultant ciphertext.
let ctr_plaintext = cipher.decrypt_ctr(&ctr_ciphertext)?;

// round trip results in the same plaintext as the original message.
assert_eq!(plaintext, ctr_plaintext); 

// for ECB mode:
let ecb_ciphertext = cipher.encrypt_ecb(plaintext);
let ecb_plaintext = cipher.decrypt_ecb(&ecb_ciphertext)?;
assert_eq!(plaintext, ecb_plaintext);

// for GCM: 
let aad = vec![0xDE, 0xAD, 0xBE, 0xEF]; // encrypt GCM takes AAD as an Option<&[u8]>.
let gcm_ciphertext = cipher.encrypt_gcm(plaintext, Some(&aad))?;

// decrypt GCM returns a tuple containing (plaintext, aad), where aad is an Option<Vec[u8]>.
let (gcm_plaintext, res_aad) = cipher.decrypt_gcm(&gcm_ciphertext)?;
assert_eq!(plaintext, gcm_plaintext);
assert_eq!(Some(aad), res_aad);
```

## Features Roadmap (complete)

Library roadmap:

- [x] AES encryption and decryption in ECB mode with PKCS#7 padding
- [x] Robust library error handling using `thiserror` crate
- [x] Counter mode of operation (CTR)
- [x] Galois/counter mode (GCM) for message authentication
- [x] GCM with additional authenticated data (AAD)
- [x] Intuitive library API
- [x] Encryption and decryption in parallel for all modes
- [x] In-code library documentation for docs.rs
- [x] Extensive integration tests from public sources
- [x] Publish to crates.io

CLI roadmap:

- [x] CLI using clap, supporting random key generation for encryption
- [x] Specify mode of operation
- [x] Accept AAD for GCM and print AAD to stdout when decrypting

## License

Licensed under either of:

- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](https://opensource.org/license/MIT)

at your option.
