# Export Compliance Notice

## Overview

Wallet Recovery CLI contains cryptographic functionality subject to export controls under various national regulations, including but not limited to the U.S. Export Administration Regulations (EAR).

## Cryptographic Algorithms Used

| Algorithm | Purpose | Key Size |
|-----------|---------|----------|
| RSA | Key pair generation for backup/recovery | 4096 bits |
| AES-GCM | Symmetric encryption of recovered keys | 256 bits |
| ECDSA (SECP256K1) | Bitcoin/Ethereum signature verification | 256 bits |
| ED25519 | Solana signature verification | 256 bits |
| SHA-256 | Hashing | 256 bits |
| RIPEMD-160 | Bitcoin address generation | 160 bits |

## U.S. Export Classification

This software is classified as:
- **ECCN**: 5D002.c.1 (software employing encryption for confidentiality)
- **License Exception**: TSR (Technology and Software Unrestricted)

Under License Exception TSR, this publicly available open-source software may be exported without a license to most destinations.

## Responsibilities

Users and distributors are responsible for:
1. Ensuring compliance with their local export/import laws
2. Not exporting to embargoed countries or sanctioned entities
3. Maintaining appropriate records as required by law

## Disclaimer

This information is provided for reference only and does not constitute legal advice. Consult with qualified legal counsel for specific compliance questions.

