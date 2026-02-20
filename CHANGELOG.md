# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2025-02-20

### Added
- Initial public release
- `generate-recovery-keypair` command for RSA-4096 key generation
  - Optional password encryption for private keys (`--encrypt-private-key`)
  - Binary DER (default) or hex-encoded output formats
- `recover` command for ECDSA (SECP256K1) and ED25519 private key recovery
  - Displays Ethereum, XRP, and Bitcoin addresses for SECP256K1 keys
  - Displays Solana address for ED25519 keys
  - Bitcoin addresses shown for both testnet (tb1...) and mainnet (bc1...)
  - Optional AES-256-GCM encryption for output files
- `decrypt` command for decrypting encrypted private key files
- `print-address` command for deriving blockchain addresses
  - Auto-detects encrypted files (PKE1 header) and prompts for password
  - `--key-type` flag to disambiguate ED25519 vs SECP256K1 keys
  - Shows all applicable addresses (EVM, XRP, Bitcoin for SECP256K1; Solana for ED25519)
- `validate-key` command for RSA key validation
- Comprehensive error handling and input validation

### Security
- RSA-4096 minimum key size requirement
- Minimum 8-character password requirement for encryption
- Secure password input (no terminal echo)
- Password confirmation for encryption operations
- Restrictive file permissions (0400) for private keys
- Memory clearing for sensitive data (passwords, keys)

