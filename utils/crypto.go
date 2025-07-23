package utils

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mr-tron/base58"
)

func GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	pkey, err := crypto.HexToECDSA(hex.EncodeToString(privateKeyBytes))
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(pkey.PublicKey).Hex(), nil
}

// GetSolanaAddressFromPrivateKeyBytes derives a Solana address from ED25519 private key bytes
func GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	// TSM SDK returns 32-byte private key (seed)
	if len(privateKeyBytes) != 32 {
		return "", fmt.Errorf("invalid ED25519 private key size: expected 32, got %d", len(privateKeyBytes))
	}

	// Create full private key from seed
	privateKey := ed25519.NewKeyFromSeed(privateKeyBytes)
	publicKey := privateKey.Public().(ed25519.PublicKey)

	// Solana addresses are base58 encoded public keys
	return base58.Encode(publicKey), nil
}
