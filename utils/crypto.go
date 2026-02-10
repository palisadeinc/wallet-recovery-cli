// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/mr-tron/base58"

	"filippo.io/edwards25519"
	"github.com/ethereum/go-ethereum/crypto"

	"golang.org/x/crypto/ripemd160" //nolint:gosec // Required for Bitcoin/XRP address derivation per BIP-0013
)

func GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	pkey, err := crypto.HexToECDSA(hex.EncodeToString(privateKeyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to convert private key to ECDSA: %w", err)
	}
	return crypto.PubkeyToAddress(pkey.PublicKey).Hex(), nil
}

// GetSolanaAddressFromPrivateKeyBytes derives a Solana address from ED25519 private key bytes
func GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	// TSM SDK returns 32-byte raw scalar in big-endian format
	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("invalid ED25519 private key size: expected 32, got %d", len(privateKeyBytes))
	}

	// TSM returns raw scalar in big-endian, but filippo.io/edwards25519 expects little-endian
	// Make a copy and reverse it
	littleEndianKey := make([]byte, 32)
	copy(littleEndianKey, privateKeyBytes)
	reverseSlice(littleEndianKey)

	// Create scalar from the little-endian bytes
	scalar, err := edwards25519.NewScalar().SetCanonicalBytes(littleEndianKey)
	if err != nil {
		return "", fmt.Errorf("failed to create scalar from private key: %w", err)
	}

	// Public key is g^{privateKey} where g is the Ed25519 base point
	publicKeyPoint := edwards25519.NewGeneratorPoint().ScalarBaseMult(scalar)
	publicKey := publicKeyPoint.Bytes()

	// Solana addresses are base58 encoded public keys
	address := base58.Encode(publicKey)

	return address, nil
}

// reverseSlice reverses a byte slice in place
func reverseSlice(b []byte) {
	l := len(b)
	for i := 0; i < l/2; i++ {
		b[i], b[l-1-i] = b[l-1-i], b[i]
	}
}

// GetXRPAddressFromPrivateKeyBytes derives an XRP address from SECP256K1 private key bytes
func GetXRPAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	// Create ECDSA private key from bytes
	privateKey := new(ecdsa.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(privateKeyBytes)
	privateKey.PublicKey.Curve = crypto.S256() // Use secp256k1 curve
	privateKey.PublicKey.X, privateKey.PublicKey.Y = privateKey.PublicKey.Curve.ScalarBaseMult(privateKeyBytes)

	// Get compressed public key (33 bytes)
	pubKeyBytes := elliptic.MarshalCompressed(privateKey.PublicKey.Curve, privateKey.PublicKey.X, privateKey.PublicKey.Y)

	// XRP address derivation:
	// 1. SHA-256 hash of the public key
	sha256Hash := sha256.Sum256(pubKeyBytes)

	// 2. RIPEMD-160 hash of the SHA-256 hash
	ripemd := ripemd160.New() //nolint:gosec // Required for XRP address derivation per XRPL spec
	ripemd.Write(sha256Hash[:])
	accountID := ripemd.Sum(nil)

	// 3. Prepend version byte (0x00 for XRP)
	payload := append([]byte{0x00}, accountID...)

	// 4. Calculate checksum (double SHA-256)
	checksum1 := sha256.Sum256(payload)
	checksum2 := sha256.Sum256(checksum1[:])
	checksum := checksum2[:4]

	// 5. Append checksum to payload
	addressBytes := make([]byte, len(payload)+len(checksum))
	copy(addressBytes, payload)
	copy(addressBytes[len(payload):], checksum)

	// 6. Base58 encode
	// XRP uses a custom alphabet: "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	xrpAlphabet := "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
	return base58EncodeWithAlphabet(addressBytes, xrpAlphabet), nil
}

// base58EncodeWithAlphabet encodes bytes using a custom alphabet
func base58EncodeWithAlphabet(input []byte, alphabet string) string {
	if len(alphabet) != 58 {
		panic("alphabet must be 58 characters")
	}

	// Convert to big int
	val := new(big.Int).SetBytes(input)
	base := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var result []byte
	for val.Cmp(zero) > 0 {
		val.DivMod(val, base, mod)
		result = append([]byte{alphabet[mod.Int64()]}, result...)
	}

	// Add leading 'r's for leading zeros
	for _, b := range input {
		if b != 0 {
			break
		}
		result = append([]byte{alphabet[0]}, result...)
	}

	return string(result)
}
