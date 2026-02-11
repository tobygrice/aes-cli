# AES in Rust
## About
Planned features:
- [x] AES encryption and decryption in ECB mode with PKCS#7 padding
- [x] CLI using clap, supporting random key generation for encryption
- [x] Robust library error handling using `thiserror` crate
- [x] Counter mode of operation (CTR)
- [x] Galois counter mode (GCM)
- [ ] GCM with AAD
- [ ] Encryption and decryption in parallel

## Usage
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
  -i, --input <INPUT>        Input file path
  -o, --output <OUTPUT>      Output file path
  -k, --key <KEY>            Key file path
      --gen-key              Generate a random key (written to path specified by key)
      --key-size <KEY_SIZE>  Only valid with --gen-key [default: 256] [possible values: 128, 192, 256]
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