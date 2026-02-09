# Test Data

This directory contains test fixtures for wallet-recovery-cli unit and integration tests.

## Contents

| File | Description |
|------|-------------|
| `valid_rsa_4096_public.pem` | Valid RSA-4096 public key in PEM format |
| `valid_rsa_4096_private.pem` | Valid RSA-4096 private key in PEM format (TEST ONLY) |
| `invalid_rsa_2048_public.pem` | Invalid RSA-2048 public key (too small for production) |
| `invalid_rsa_2048_private.pem` | Invalid RSA-2048 private key (too small for production) |

## Security Notice

⚠️ **These keys are for testing only!**

Never use test keys in production. All private keys in this directory are intentionally weak or well-known test keys and should never be used for any real cryptographic operations.

## Usage

These fixtures are used in the following test files:
- `utils/crypto_test.go` - RSA key validation and cryptographic operations
- `utils/encryption_test.go` - Encryption/decryption tests
- `utils/recovery_test.go` - Recovery kit processing tests

## Regenerating Test Keys

If you need to regenerate these test keys, run:

```bash
cd wallet-recovery-cli/testdata

# Generate RSA-4096 test keypair
openssl genrsa -out valid_rsa_4096_private.pem 4096
openssl rsa -in valid_rsa_4096_private.pem -pubout -out valid_rsa_4096_public.pem

# Generate invalid RSA-2048 key (for negative tests)
openssl genrsa -out invalid_rsa_2048_private.pem 2048
openssl rsa -in invalid_rsa_2048_private.pem -pubout -out invalid_rsa_2048_public.pem
```

