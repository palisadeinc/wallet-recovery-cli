# Key Formats

This document describes the cryptographic key formats used by Wallet Recovery CLI.

## RSA Public Key

### Format: PKIX DER

The `generate-recovery-keypair` command outputs the public key in PKIX (Public Key Infrastructure X.509) DER (Distinguished Encoding Rules) format.

**Structure:**
```
SEQUENCE {
  SEQUENCE {
    OBJECT IDENTIFIER rsaEncryption (1.2.840.113549.1.1.1)
    NULL
  }
  BIT STRING {
    SEQUENCE {
      INTEGER modulus (n)
      INTEGER publicExponent (e)
    }
  }
}
```

**Minimum Requirements:**
- Key size: 4096 bits (RSA-4096)
- Public exponent: 65537 (0x10001)

### File Extension
- `.pem` - PEM encoded (Base64 with headers)
- `.der` - Raw binary DER

### Conversion Examples

```bash
# Convert DER to PEM
openssl rsa -pubin -inform DER -in public.der -outform PEM -out public.pem

# Convert PEM to DER
openssl rsa -pubin -inform PEM -in public.pem -outform DER -out public.der

# View key details
openssl rsa -pubin -in public.pem -text -noout
```

## RSA Private Key

### Format: PKCS#1 or PKCS#8 DER

**PKCS#1 Structure:**
```
RSAPrivateKey ::= SEQUENCE {
  version           INTEGER,
  modulus           INTEGER,
  publicExponent    INTEGER,
  privateExponent   INTEGER,
  prime1            INTEGER,
  prime2            INTEGER,
  exponent1         INTEGER,
  exponent2         INTEGER,
  coefficient       INTEGER
}
```

### Security
- File permissions: 0400 (owner read-only)
- Never transmit unencrypted
- Store in HSM or secure vault

## Encrypted Private Key

### Format: AES-256-GCM with Custom Header

```
┌─────────────────────────────────────┐
│ Magic Header: "PALISADE_ENC_V1"     │ 16 bytes
├─────────────────────────────────────┤
│ Salt (for PBKDF2)                   │ 32 bytes
├─────────────────────────────────────┤
│ Nonce (IV)                          │ 12 bytes
├─────────────────────────────────────┤
│ Encrypted Data + Auth Tag           │ variable
└─────────────────────────────────────┘
```

**Key Derivation:**
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 100,000
- Salt: 32 bytes random
- Output: 32-byte AES key

**Encryption:**
- Algorithm: AES-256-GCM
- Nonce: 12 bytes random
- Auth tag: 16 bytes (included in ciphertext)

## Recovered Private Keys

### ECDSA (SECP256K1)
- 32 bytes raw scalar
- Used for: Bitcoin, Ethereum

### ED25519
- 32 bytes seed or 64 bytes full keypair
- Used for: Solana

## Address Derivation

### Ethereum (SECP256K1)
1. Derive public key from private key
2. Take Keccak256 hash of uncompressed public key (64 bytes, no prefix)
3. Take last 20 bytes
4. Prefix with "0x" and hex encode

### Solana (ED25519)
1. Derive public key from seed (32 bytes)
2. Base58 encode the public key (32 bytes)

