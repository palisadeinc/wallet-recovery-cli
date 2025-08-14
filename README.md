# MPC Recovery Tool

A command-line interface (CLI) tool for performing MPC (Multi-Party Computation) recovery operations using cryptographic primitives. This tool helps recover both ECDSA (SECP256K1) and ED25519 private keys using recovery data and RSA keypairs.

## Overview

This tool provides functionality for:
- Generating RSA keypairs for MPC recovery purposes
- Recovering ECDSA (SECP256K1) private keys for Ethereum/EVM chains
- Recovering ED25519 private keys for Solana
- Decrypting encrypted private key files generated during the recovery process
- Printing blockchain addresses (Ethereum for SECP256K1, Solana for ED25519)

## Installation

```bash
# Clone the repository
git clone https://github.com/palisadeinc/mpc-recovery.git
cd mpc-recovery

# Build the binary
go build -o recovery
```

## Usage

### Generate Recovery Keypair

Generate an RSA 4096-bit keypair for MPC recovery:

```bash
./recovery generate-recovery-keypair --private-key-file=private.der --public-key-file=public.der
```

Required flags:
- `--private-key-file`: Path where the private key will be saved (file must not exist)
- `--public-key-file`: Path where the public key will be saved (file must not exist)

The keys are saved in hex-encoded DER format.

The resulting content of the file specified in the `--public-key-file` flag can be used as a backup recovery key in the Palisade console.

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
6. Displays the corresponding blockchain address (Ethereum for SECP256K1, Solana for ED25519).
7. The recovered private key is printed to standard output in base64 format or saved to file.

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
# Plain-text private key file
./recovery print-address --private-key-file=private.der

# Encrypted private key file
./recovery print-address --private-key-file=recovered.enc --encrypted
```

Required flags:
- `--private-key-file`: Path to the (plain-text or encrypted) private key file.

Optional flags:
- `--encrypted`: Set to `true` if the private key file is encrypted (default `false`).

The command prints the corresponding blockchain address to standard output:
- For SECP256K1 keys: EVM-compatible Ethereum address
- For ED25519 keys: Solana address (hex-encoded public key)

## Security Considerations

- Keep RSA private keys secure and protected
- The tool validates recovery data before attempting recovery
- Generated private keys are stored with restricted file permissions (0400)

## Dependencies

- [Cobra](https://github.com/spf13/cobra) - CLI command structure
- [Viper](https://github.com/spf13/viper) - Configuration management

## License

Apache License (as specified in configuration) 