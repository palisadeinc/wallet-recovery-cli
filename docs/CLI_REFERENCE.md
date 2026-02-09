# Wallet Recovery CLI Reference

## Overview

The Wallet Recovery CLI (`recovery`) is a command-line tool for MPC (Multi-Party Computation) recovery operations using cryptographic primitives. It enables secure wallet key recovery through a series of cryptographic operations.

**Version**: Use `recovery --version` or `recovery -v` to display version information.

---

## Global Flags

| Flag | Type | Description |
|------|------|-------------|
| `-v, --version` | boolean | Print version information |
| `-h, --help` | boolean | Display help information |

---

## Commands

### generate-recovery-keypair

Generate an RSA-4096 key pair for wallet backup and recovery.

**Synopsis**
```
recovery generate-recovery-keypair --private-key-file=<path> --public-key-file=<path> [--format=<der|hex>] [--encrypt-private-key]
```

**Description**

Creates a new RSA-4096 key pair used in the MPC recovery process:
- The PUBLIC key is uploaded to Palisade for encrypting wallet backups
- The PRIVATE key is kept secure by you for recovering wallet keys

The public key is output in PKIX DER format. By default, the output is binary DER (industry standard). Use `--format=hex` for hex-encoded output (legacy format). The public key should be uploaded through the Palisade Customer Portal or API. The private key can optionally be encrypted with a password for additional security.

**Output Formats**

| Format | Description | File Size | Use Case |
|--------|-------------|-----------|----------|
| `der` (default) | Binary DER format | ~550 bytes | Industry standard, compatible with OpenSSL |
| `hex` | Hex-encoded DER | ~1100 characters | Legacy format, text-based |

**Flags**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--private-key-file` | string | - | Yes | File path to save the private key. Must not exist. |
| `--public-key-file` | string | - | Yes | File path to save the public key. Must not exist. |
| `--format` | string | `der` | No | Output format for public key: `der` (binary) or `hex` (hex-encoded) |
| `--encrypt-private-key` | boolean | false | No | Encrypt the private key with a password |

**Examples**

```bash
# Generate a key pair with binary DER output (default)
recovery generate-recovery-keypair \
  --private-key-file=private.der \
  --public-key-file=public.der

# Generate with hex-encoded output (legacy format)
recovery generate-recovery-keypair \
  --private-key-file=private.der \
  --public-key-file=public.hex \
  --format=hex

# Generate with password-encrypted private key
recovery generate-recovery-keypair \
  --private-key-file=private.der \
  --public-key-file=public.der \
  --encrypt-private-key

# Generate with custom output directory
recovery generate-recovery-keypair \
  --private-key-file=./keys/private.der \
  --public-key-file=./keys/public.der
```

**Security Notes**

- Store the private key securely (e.g., hardware security module, secure vault)
- Never share or upload the private key
- Back up the private key to a secure location
- If using `--encrypt-private-key`, use a strong password (minimum 8 characters)
- The private key file is created with restricted permissions (0400)
- Consider using a password manager or HSM for password storage

**Related Commands**: `recover`, `validate-private-key`

---

### recover

Recover a private key from recovery data using cryptographic primitives.

**Synopsis**
```
recovery recover \
  --recovery-kit-file=<path> \
  --private-key-file=<path> \
  --quorum-id=<uuid> \
  --key-id=<uuid> \
  [--key-type=<type>] \
  [--output-file=<path>] \
  [--encrypt-output=<bool>]
```

**Description**

Performs the core MPC recovery operation. Takes a recovery kit file (downloaded from Palisade) and your RSA private key to recover the original wallet private key. Supports both SECP256K1 (Ethereum/EVM) and ED25519 (Solana) key types.

**Recovery Process**

1. Reads and parses the recovery kit file and RSA private key
2. Validates that the public key derived from the RSA private key matches the public key stored in the recovery data
3. Determines the key type (from flag or recovery kit metadata)
4. Validates the integrity of the recovery data using the appropriate algorithm
5. Recovers the private key using the recovery data and RSA private key
6. Displays the corresponding blockchain address
7. Optionally saves the recovered private key to a file (encrypted or plain)

**Flags**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--recovery-kit-file` | string | - | Yes | Local file path to the recovery data file from S3 |
| `--private-key-file` | string | - | Yes | File path to RSA-4096 bit private key (hex-encoded DER or encrypted) |
| `--quorum-id` | string | - | Yes | Quorum ID (UUID format) |
| `--key-id` | string | - | Yes | Key ID (UUID format) |
| `--key-type` | string | SECP256K1 | No | Key algorithm type: SECP256K1 or ED25519 |
| `--output-file` | string | - | No | File path to save the recovered private key |
| `--encrypt-output` | boolean | true | No | Encrypt the output file using the private key |

**Supported Key Types**

- **SECP256K1**: For Ethereum and EVM-compatible chains (displays Ethereum and XRP addresses)
- **ED25519**: For Solana (displays Solana address)

**Examples**

```bash
# Recover a SECP256K1 key and display the address
recovery recover \
  --recovery-kit-file=recovery_kit.json \
  --private-key-file=private.der \
  --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
  --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8

# Recover an ED25519 key for Solana
recovery recover \
  --recovery-kit-file=recovery_kit.json \
  --private-key-file=private.der \
  --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
  --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  --key-type=ED25519

# Recover and save to encrypted file
recovery recover \
  --recovery-kit-file=recovery_kit.json \
  --private-key-file=private.der \
  --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
  --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  --output-file=recovered_key.enc \
  --encrypt-output=true

# Recover and save to plain text file (not recommended)
recovery recover \
  --recovery-kit-file=recovery_kit.json \
  --private-key-file=private.der \
  --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
  --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  --output-file=recovered_key.der \
  --encrypt-output=false
```

**Security Notes**

- The recovered private key is sensitive and should be handled with care
- By default, output files are encrypted (`--encrypt-output=true`)
- If your RSA private key is encrypted, you will be prompted for the password
- The command validates recovery data integrity before attempting recovery
- Consider using the `decrypt` command to decrypt saved keys only when needed

**Related Commands**: `generate-recovery-keypair`, `decrypt`, `print-address`

---

### decrypt

Decrypt an encrypted recovery private key file.

**Synopsis**
```
recovery decrypt \
  --encrypted-private-key-file=<path> \
  --decrypted-output-file=<path>
```

**Description**

Decrypts a private key file that was encrypted during the recovery process. Reads the encrypted file, prompts for the password, and writes the decrypted key to a new file. The original encrypted file is not modified.

**Flags**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--encrypted-private-key-file` | string | - | Yes | Path to file containing encrypted private key. Must exist and be readable. |
| `--decrypted-output-file` | string | - | Yes | Path to file containing decrypted private key. Must not exist. |

**Use Cases**

- Decrypt a recovered private key saved with `--encrypt-output=true`
- Decrypt a recovery keypair generated with `--encrypt-private-key`
- Temporarily decrypt a key for use in other tools

**Examples**

```bash
# Decrypt a recovered private key
recovery decrypt \
  --encrypted-private-key-file=recovered_key.enc \
  --decrypted-output-file=recovered_key.der

# Decrypt a recovery keypair
recovery decrypt \
  --encrypted-private-key-file=private.der.enc \
  --decrypted-output-file=private.der

# Decrypt and use with another tool
recovery decrypt \
  --encrypted-private-key-file=wallet_key.enc \
  --decrypted-output-file=/tmp/wallet_key.der
# Then use /tmp/wallet_key.der with your wallet software
# Remember to securely delete /tmp/wallet_key.der when done
```

**Workflow**

1. Run the decrypt command with the encrypted file path
2. Enter the password when prompted
3. The decrypted key is written to the output file
4. Use the decrypted key as needed
5. Securely delete the decrypted file when no longer needed

**Security Notes**

- The decrypted output file is created with restricted permissions (0400)
- Only decrypt keys when you need to use them
- Securely delete decrypted files after use (consider using `shred` or `srm`)
- Keep encrypted files as your primary storage method
- The original encrypted file is never modified
- Ensure the output file path does not already exist

**Related Commands**: `recover`, `print-address`, `validate-private-key`

---

### print-address

Derive and print the blockchain address from a recovered private key.

**Synopsis**
```
recovery print-address \
  --private-key-file=<path> \
  [--encrypted]
```

**Description**

Reads a private key file (encrypted or plain text) and derives the corresponding blockchain address. Supports multiple key types and chains:
- SECP256K1 keys: Derives EVM-compatible Ethereum addresses
- ED25519 keys: Derives Solana addresses

The command automatically detects the key type from the private key content and displays the appropriate address format.

**Flags**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--private-key-file` | string | - | Yes | Path to file containing private key. Must exist and be readable. |
| `--encrypted` | boolean | false | No | Whether the private key file is encrypted. |

**Supported Chains**

- Ethereum and EVM-compatible chains (SECP256K1)
- Solana (ED25519)

**Examples**

```bash
# Print address from plain-text private key
recovery print-address --private-key-file=recovered_key.der

# Print address from encrypted private key
recovery print-address \
  --private-key-file=recovered_key.enc \
  --encrypted

# Print address from a recovery keypair
recovery print-address --private-key-file=private.der

# Print address from encrypted recovery keypair
recovery print-address \
  --private-key-file=private.der.enc \
  --encrypted

# Verify address matches your wallet
recovery print-address --private-key-file=recovered_key.der
# Compare output with your wallet's address to verify recovery was successful
```

**Workflow**

1. Run the command with your private key file
2. If encrypted, you will be prompted for the password
3. The command derives the public key from the private key
4. The corresponding blockchain address is printed to stdout
5. Verify the address matches your expected wallet address

**Security Notes**

- The private key is read into memory but not stored
- If the file is encrypted, the password is read securely from the terminal
- The command does not modify the private key file
- Use this command to verify recovery was successful before using the key
- The address is derived deterministically from the private key

**Related Commands**: `recover`, `decrypt`, `validate-private-key`

---

### validate-private-key

Validate password for an encrypted private key.

**Synopsis**
```
recovery validate-private-key --private-key-file=<path>
```

**Description**

Tests whether a password can successfully decrypt an encrypted private key file without modifying the original file. Useful for:
- Verifying you have the correct password before critical operations
- Testing password recovery procedures
- Validating key file integrity
- Confirming a key is properly encrypted

**Validation Process**

1. Reads the private key file
2. Detects if the file is encrypted (checks for encryption header)
3. If encrypted, prompts for the password and attempts decryption
4. Validates the decrypted content is a valid RSA private key
5. Reports success or failure without modifying the file

**Flags**

| Flag | Type | Default | Required | Description |
|------|------|---------|----------|-------------|
| `--private-key-file` | string | - | Yes | Path to the private key file to validate |

**Examples**

```bash
# Validate an encrypted recovery keypair
recovery validate-private-key --private-key-file=private.der.enc
# Output: "Validation successful: password is correct and private key is valid"

# Validate an encrypted recovered key
recovery validate-private-key --private-key-file=recovered_key.enc

# Validate a plain-text key (no password needed)
recovery validate-private-key --private-key-file=private.der
# Output: "Private key file is not encrypted. No password validation needed."

# Test password before recovery operation
recovery validate-private-key --private-key-file=private.der.enc
# If validation succeeds, you can proceed with the 'recover' command
```

**Workflow**

1. Run the command with your encrypted key file
2. Enter the password when prompted
3. The command validates the password and key integrity
4. If successful, you can use the key with other commands
5. If failed, verify the password and try again

**Security Notes**

- The original file is never modified
- The password is read securely from the terminal
- Decrypted content is cleared from memory after validation
- Supports both PKCS1 and PKCS8 RSA private key formats
- Use this command to verify key integrity periodically
- If validation fails, check that you have the correct password

**Related Commands**: `generate-recovery-keypair`, `recover`, `decrypt`

---

## Common Workflows

### Workflow 1: Generate and Store Recovery Keypair

```bash
# 1. Generate keypair with password encryption
recovery generate-recovery-keypair \
  --private-key-file=private.der \
  --public-key-file=public.der \
  --encrypt-private-key

# 2. Upload public.der to Palisade Customer Portal

# 3. Validate the encrypted private key
recovery validate-private-key --private-key-file=private.der

# 4. Store private.der securely
```

### Workflow 2: Recover Wallet Key

```bash
# 1. Download recovery_kit.json from Palisade

# 2. Recover the private key
recovery recover \
  --recovery-kit-file=recovery_kit.json \
  --private-key-file=private.der \
  --quorum-id=<your-quorum-id> \
  --key-id=<your-key-id> \
  --output-file=recovered_key.enc \
  --encrypt-output=true

# 3. Verify the recovered address
recovery print-address \
  --private-key-file=recovered_key.enc \
  --encrypted

# 4. Decrypt only when needed
recovery decrypt \
  --encrypted-private-key-file=recovered_key.enc \
  --decrypted-output-file=recovered_key.der

# 5. Use recovered_key.der with your wallet software

# 6. Securely delete the decrypted file
shred -u recovered_key.der
```

### Workflow 3: Verify Key Integrity

```bash
# Validate encrypted recovery keypair
recovery validate-private-key --private-key-file=private.der

# Validate encrypted recovered key
recovery validate-private-key --private-key-file=recovered_key.enc

# Print address to verify key is correct
recovery print-address \
  --private-key-file=recovered_key.enc \
  --encrypted
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Command executed successfully |
| 1 | Command failed (see error message for details) |

---

## File Formats

### Private Key Files

- **Plain text**: Hex-encoded DER format (PKCS1 or PKCS8)
- **Encrypted**: Binary format with encryption header, created with `--encrypt-private-key` or `--encrypt-output`
- **Permissions**: Created with restricted permissions (0400) for security

### Public Key Files

- **Format**: Hex-encoded PKIX DER format
- **Permissions**: Created with restricted permissions (0400)

### Recovery Kit Files

- **Format**: Base64-encoded JSON containing recovery data
- **Source**: Downloaded from Palisade

---

## Security Best Practices

1. **Key Storage**: Store private keys in secure locations (HSM, vault, encrypted storage)
2. **Password Protection**: Always encrypt private keys with strong passwords (minimum 8 characters)
3. **File Permissions**: Verify files have restricted permissions (0400)
4. **Temporary Files**: Securely delete decrypted files using `shred` or `srm`
5. **Password Input**: Passwords are read securely from the terminal (not echoed)
6. **Memory Clearing**: Sensitive data is cleared from memory after use
7. **Validation**: Always validate keys before critical operations
8. **Backups**: Back up encrypted private keys to secure locations
9. **Access Control**: Restrict access to key files and recovery kits
10. **Audit**: Keep records of key generation and recovery operations

---

## Troubleshooting

### "Password must be at least 8 characters"
Ensure your password is at least 8 characters long when encrypting keys.

### "Passwords do not match"
Re-enter the password carefully. Passwords are case-sensitive.

### "Recovery public key does not match the private key"
Ensure you're using the correct private key file that corresponds to the recovery kit.

### "Validation failed: incorrect password or corrupted file"
Verify the password is correct. If the file is corrupted, try restoring from a backup.

### "Not a valid private key file"
Ensure the file contains a valid hex-encoded RSA private key or is properly encrypted.

---

## Additional Resources

- See `ARCHITECTURE.md` for technical implementation details
- See `KEY_FORMATS.md` for detailed key format specifications
- See `EXPORT_COMPLIANCE.md` for export and compliance information

