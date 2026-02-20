# Wallet Recovery CLI

[![Build Status](https://github.com/palisadeinc/wallet-recovery-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/palisadeinc/wallet-recovery-cli/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/palisadeinc/wallet-recovery-cli)](https://goreportcard.com/report/github.com/palisadeinc/wallet-recovery-cli)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

A command-line interface (CLI) tool for performing MPC (Multi-Party Computation) recovery operations using cryptographic primitives. This tool helps recover both ECDSA (SECP256K1) and ED25519 private keys using recovery data and RSA keypairs.

## Overview

This tool provides functionality for:
- Generating RSA keypairs for MPC recovery purposes
- Recovering ECDSA (SECP256K1) private keys for Ethereum/EVM, XRP, and Bitcoin
- Recovering ED25519 private keys for Solana
- Decrypting encrypted private key files generated during the recovery process
- Printing blockchain addresses (Ethereum/XRP/Bitcoin for SECP256K1, Solana for ED25519)

## Installation

### Using Go Install

```bash
go install github.com/palisadeinc/wallet-recovery-cli@latest
```

### Download Binary from Releases

Visit the [Releases](https://github.com/palisadeinc/wallet-recovery-cli/releases) page to download pre-built binaries for your platform.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/palisadeinc/wallet-recovery-cli.git
cd wallet-recovery-cli

# Build the binary
go build -o recovery
```

## Usage

### Generate Recovery Keypair

Generate an RSA 4096-bit keypair for MPC recovery:

```bash
# Generate with binary DER output (default, industry standard)
./recovery generate-recovery-keypair --private-key-file=private.der --public-key-file=public.der

# Generate with hex-encoded output (legacy format)
./wallet-recovery-cli generate-recovery-keypair --private-key-file=private.der --public-key-file=public.hex --format=hex
```

Required flags:
- `--private-key-file`: Path where the private key will be saved (file must not exist)
- `--public-key-file`: Path where the public key will be saved (file must not exist)

Optional flags:
- `--format`: Output format for public key: `der` (binary, default) or `hex` (hex-encoded)
- `--encrypt-private-key`: Encrypt the private key with a password

The public key file can be uploaded as a backup recovery key in the Palisade console. Both binary DER and hex-encoded formats are accepted.

### Recover Private Key

Recover a private key from recovery data (supports both ECDSA/SECP256K1 and ED25519):

```bash
# For ECDSA/SECP256K1 (Ethereum) - default
./recovery recover \
  --recovery-kit-file=recovery-kit.b64 \
  --private-key-file=private.der \
  --quorum-id=<UUID> \
  --key-id=<UUID> \
  --output-file=recovered.enc    # Optional – save to file instead of stdout

# For ED25519 (Solana)
./recovery recover \
  --recovery-kit-file=recovery-kit.b64 \
  --private-key-file=private.der \
  --quorum-id=<UUID> \
  --key-id=<UUID> \
  --key-type=ED25519 \
  --output-file=recovered.enc    # Optional – save to file instead of stdout
```

Required flags:
- `--recovery-kit-file`: Path to the recovery data file (base64-encoded JSON, typically downloaded from the customer's S3 bucket)
- `--private-key-file`: Path to the RSA private key file (hex-encoded DER, PKCS#1 or PKCS#8 format)
- `--quorum-id`: UUID of the quorum
- `--key-id`: UUID of the key

Optional flags:
- `--key-type`: Key algorithm type: SECP256K1 (default) or ED25519
- `--output-file`: Path where the recovered private key should be written. If omitted, the key is printed to stdout.
- `--encrypt-output`: Whether to AES-256 encrypt the output file (default `true`). When enabled you will be prompted for a password.

The recovery operation performs the following steps:
1. Reads and parses the recovery kit file and the RSA private key file.
2. Validates that the public key derived from the provided RSA private key matches the public key stored within the recovery data.
3. Determines the key type (from flag or recovery kit metadata).
4. Validates the integrity of the recovery data using the appropriate algorithm (ECDSA for SECP256K1, Schnorr for ED25519).
5. If validations pass, recovers the private key using the recovery data and the provided RSA private key.
6. Displays the corresponding blockchain addresses:
   - For SECP256K1: Ethereum, XRP, and Bitcoin addresses (both testnet and mainnet)
   - For ED25519: Solana address
7. The recovered private key is printed to standard output in base64 format or saved to file.

**Note**: When using `--encrypt-output=true`, passwords must be at least 8 characters.

### Decrypt Encrypted Private Key File

Decrypt a private key file that was encrypted by the `recover` command:

```bash
./recovery decrypt --encrypted-private-key-file=recovered.enc --decrypted-output-file=private.der
```

Required flags:
- `--encrypted-private-key-file`: Path to the encrypted private key file (must exist)
- `--decrypted-output-file`: Path where the decrypted private key will be written (must not exist)

The command will prompt for the password that was used during encryption.

### Print Address

Print the blockchain address derived from a recovered private key:

```bash
# Plain-text private key file (auto-detects key type)
./recovery print-address --private-key-file=private.der

# Encrypted private key file (auto-detected, will prompt for password)
./recovery print-address --private-key-file=recovered.enc

# Specify key type explicitly (useful when auto-detection is ambiguous)
./recovery print-address --private-key-file=private.der --key-type=ED25519
```

Required flags:
- `--private-key-file`: Path to the (plain-text or encrypted) private key file.

Optional flags:
- `--key-type`: Key algorithm type: `SECP256K1` or `ED25519`. If not specified, auto-detects based on key content. Note: Both key types produce 32-byte private keys, so specify this flag if auto-detection produces incorrect results.

The command automatically detects encrypted files (by checking for the PKE1 header) and prompts for the password.

The command prints the corresponding blockchain addresses to standard output:
- For SECP256K1 keys: EVM-compatible (Ethereum), XRP, and Bitcoin addresses (both testnet and mainnet)
- For ED25519 keys: Solana address

## Security Considerations

- Keep RSA private keys secure and protected
- The tool validates recovery data before attempting recovery
- Generated private keys are stored with restricted file permissions (0400)

## Dependencies

- [Cobra](https://github.com/spf13/cobra) - CLI command structure
- [Viper](https://github.com/spf13/viper) - Configuration management

## Troubleshooting

### File Permission Errors

**Issue**: `permission denied` when reading or writing files

**Solution**:
- Ensure you have read permissions for input files: `chmod 644 <file>`
- Ensure the directory where you're writing output files is writable: `chmod 755 <directory>`
- For private key files, the tool automatically sets restrictive permissions (0400) after creation

### Invalid Key Format Errors

**Issue**: `invalid key format` or `failed to parse key`

**Solution**:
- Verify the private key file is in hex-encoded DER format (PKCS#1 or PKCS#8)
- Ensure the recovery kit file is valid base64-encoded JSON
- Check that you're using the correct key file for the recovery operation
- Verify the key file hasn't been corrupted or modified

### Password Mismatch Errors

**Issue**: `password mismatch` or `decryption failed` when decrypting files

**Solution**:
- Ensure you're entering the correct password used during encryption
- Note that passwords are case-sensitive
- If you've forgotten the password, the encrypted file cannot be recovered
- For the `decrypt` command, make sure you're using the same password that was set during the `recover` command with `--encrypt-output=true`

## Export Compliance

This software contains cryptographic functionality and may be subject to export controls.

This software uses:
- RSA-4096 for asymmetric encryption
- AES-256-GCM for symmetric encryption
- ECDSA (SECP256K1) and ED25519 for digital signatures

Users are responsible for ensuring compliance with applicable export control laws and regulations in their jurisdiction.

## License

Apache License (as specified in configuration)