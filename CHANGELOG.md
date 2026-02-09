# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - YYYY-MM-DD

### Added
- Initial public release
- `generate-recovery-keypair` command for RSA-4096 key generation
- `recover` command for ECDSA (SECP256K1) and ED25519 private key recovery
- `decrypt` command for decrypting encrypted private key files
- `print-address` command for deriving blockchain addresses
- `validate-private-key` command for key validation
- AES-256-GCM encryption for recovered keys
- Support for both Ethereum and Solana address derivation
- Comprehensive error handling and input validation

### Security
- RSA-4096 minimum key size requirement
- Secure password input (no echo)
- Restrictive file permissions (0400) for private keys
- Memory clearing for sensitive data

