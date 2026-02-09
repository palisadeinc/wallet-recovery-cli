# Architecture

This document describes the high-level architecture of Wallet Recovery CLI.

## Overview

Wallet Recovery CLI is a command-line tool for generating RSA key pairs and recovering MPC wallet private keys from Palisade backup recovery kits.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Wallet Recovery CLI                          │
├─────────────────────────────────────────────────────────────────────┤
│                            Commands                                  │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │   generate   │ │   recover    │ │   decrypt    │ │print-address│ │
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────────────┘ │
├─────────────────────────────────────────────────────────────────────┤
│                          Core Packages                               │
│  ┌──────────────────────────────┐ ┌────────────────────────────────┐│
│  │          utils/              │ │          models/               ││
│  │  - crypto.go (key ops)       │ │  - models.go (data types)     ││
│  │  - encryption.go (AES-GCM)   │ │                                ││
│  │  - file.go (file I/O)        │ │                                ││
│  │  - recovery.go (TSM SDK)     │ │                                ││
│  └──────────────────────────────┘ └────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       External Dependencies                          │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌─────────────┐ │
│  │  TSM SDK     │ │  go-ethereum │ │ go-solana    │ │   Cobra     │ │
│  │  (Blockdaemon│ │  (addresses) │ │  (ED25519)   │ │   (CLI)     │ │
│  └──────────────┘ └──────────────┘ └──────────────┘ └─────────────┘ │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
wallet-recovery-cli/
├── cmd/                    # Command implementations
│   ├── root.go            # Root command, version handling
│   ├── generate/          # Key pair generation
│   ├── recover/           # Key recovery from backup
│   ├── decrypt/           # Decrypt encrypted key files
│   ├── print_address/     # Derive blockchain addresses
│   └── validate_key/      # Validate RSA public keys
├── models/                # Data structures
│   └── models.go          # RecoveryKit, ShareInfo, etc.
├── utils/                 # Utility packages
│   ├── crypto.go          # RSA, ECDSA, ED25519 operations
│   ├── encryption.go      # AES-256-GCM encryption
│   ├── file.go            # Secure file operations
│   └── recovery.go        # TSM SDK wrapper
├── testdata/              # Test fixtures
├── vendor/                # Vendored dependencies
└── main.go               # Entry point
```

## Key Flows

### Key Pair Generation
1. Generate RSA-4096 key pair using crypto/rand
2. Encode public key in PKIX DER format
3. Write both keys to files with secure permissions (0400)

### Key Recovery
1. Load RSA private key from file
2. Parse recovery kit JSON
3. For each wallet share:
   - Decrypt share using RSA-OAEP
   - Recombine using TSM SDK
4. Output recovered private key (optionally encrypted)

### Address Derivation
- SECP256K1: Ethereum-style Keccak256 address
- ED25519: Base58-encoded Solana address

## Security Considerations

See [SECURITY.md](../SECURITY.md) for security practices and vulnerability reporting.

## Testing

See [PRE_RELEASE_CHECKLIST.md](PRE_RELEASE_CHECKLIST.md) for testing requirements.

