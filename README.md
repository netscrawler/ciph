# RSA File Encryption Utility

A high-performance command-line tool for file encryption using RSA algorithm with parallel processing support.

## Features

- RSA key generation with customizable key size
- Parallel processing for encryption and decryption
- Multi-threaded key generation
- Progress bar visualization
- Buffered I/O operations
- Custom key file paths support
- Configurable number of worker threads

## Installation

```bash
# Clone the repository
git clone <https://github.com/netscrawler/ciph>

# Install dependencies
go get github.com/schollz/progressbar/v3
```

## Usage

### Key Generation

Generate a new RSA key pair:

```bash
# Default 2048-bit keys
go run main.go -g

# Custom key size (e.g., 4096 bits)
go run main.go -g -size 4096

# Custom key file names
go run main.go -g -size 4096 -private my_private.pem -public my_public.pem
```

### File Encryption

Encrypt a file using a public key:

```bash
# Using default key names
go run main.go -e -in document.pdf -out document.pdf.enc

# Using custom public key
go run main.go -e -in document.pdf -out document.pdf.enc -public my_public.pem

# With custom number of worker threads
go run main.go -e -in document.pdf -out document.pdf.enc -workers 4
```

### File Decryption

Decrypt a file using a private key:

```bash
# Using default key names
go run main.go -d -in document.pdf.enc -out document_decrypted.pdf

# Using custom private key
go run main.go -d -in document.pdf.enc -out document_decrypted.pdf -private my_private.pem

# With custom number of worker threads
go run main.go -d -in document.pdf.enc -out document_decrypted.pdf -workers 4
```

## Command Line Arguments

| Flag | Description | Default |
|------|-------------|---------|
| `-g` | Generate new key pair | - |
| `-e` | Encryption mode | - |
| `-d` | Decryption mode | - |
| `-in` | Input file path | Required |
| `-out` | Output file path | Required |
| `-size` | Key size in bits | 2048 |
| `-workers` | Number of worker threads | Number of CPU cores |
| `-private` | Private key file path | private.pem |
| `-public` | Public key file path | public.pem |

## Security Notes

- Keep private keys secure and never share them
- Use key size of at least 2048 bits for adequate security
- Back up your keys in a secure location
- Generated private keys have 600 permissions (user read/write only)
- Generated public keys have 644 permissions (user read/write, others read)

## Performance

The utility uses parallel processing for:
- Key generation (finding prime numbers)
- File encryption/decryption operations
- I/O operations (buffered reading/writing)

Performance depends on:
- CPU cores available
- Key size
- File size
- Storage speed
- Available memory

## Requirements

- Go 1.16 or higher
- `github.com/schollz/progressbar/v3` package

## Limitations

- Maximum file size depends on available memory
- Very large files might require significant processing time
- Key generation time increases with key size

## Error Handling

The utility includes comprehensive error handling for:
- File operations
- Key generation/loading
- Encryption/decryption processes
- Invalid parameters

## Building From Source

```bash
# Build executable
go build -o ciph main.go

# Run executable
./ciph [flags]
```

## Contributing

Feel free to submit issues and enhancement requests.

## License

NONE

## Author

[netscrawler](https://github.com/netscrawler)

## Last Updated
2025-01-30
