# AES in Rust
## About
Library roadmap:
- [x] AES encryption and decryption in ECB mode with PKCS#7 padding
- [x] Robust library error handling using `thiserror` crate
- [x] Counter mode of operation (CTR)
- [x] Galois/counter mode (GCM) for message authentication
- [x] GCM with AAD
- [x] Major library API overhaul
- [ ] Encryption and decryption in parallel
- [x] In-code library documentation for crates.io
- [ ] Publish to crates.io

CLI roadmap:
- [x] CLI using clap, supporting random key generation for encryption
- [x] Specify mode of operation
- [x] Accept AAD for GCM and print AAD to stdout when decrypting
- [ ] Read, encrypt, write in fixed-size buffer blocks (don't load massive files into RAM)

## CLI Usage
```
Usage: aes.exe <COMMAND>

Commands:
  encrypt  Encrypt input to output
  decrypt  Decrypt input to output
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

### Encryption
```
Encrypt input to output

Usage: aes.exe encrypt [OPTIONS] --input <INPUT> --output <OUTPUT> --key <KEY>

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
```
Decrypt input to output

Usage: aes.exe decrypt --input <INPUT> --output <OUTPUT> --key <KEY>

Options:
  -i, --input <INPUT>    Input file path
  -o, --output <OUTPUT>  Output file path
  -k, --key <KEY>        Key file path
  -h, --help             Print help
```

## Library Usage
AesKey struct (stores key bytes)
AesCipher struct (stores round keys)

```
// AesKey::random(size: KeySize) -> Result<AesKey> // potential rand failure
// AesKey::try_from_slice(key: &[u8]) -> Result<AesKey> // potential invalid key size

// AesCipher::new(key: &AesKey) -> AesCipher // no potential for failure

let key = AesKey::random(aes::KeySize::Bits256)?;
fs::write(key_path, &key.as_bytes())?;

let cipher = AesCipher::new(&key);

let ciphertext = cipher.encrypt_ecb(&plaintext); // no potential for failure
let plaintext = cipher.decrypt_ecb(&ciphertext); // no potential for failure

let ciphertext = cipher.encrypt_ctr(&plaintext)?; // potential ctr overflow
let plaintext = cipher.decrypt_ctr(&ciphertext)?; // potential ctr overflow

let ciphertext = cipher.encrypt_gcm(&plaintext, &aad)?; // potential ctr overflow
let (plaintext, aad) = cipher.decrypt_gcm(&ciphertext)?; // potential ctr overflow, potential invalid tag
```