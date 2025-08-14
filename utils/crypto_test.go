package utils

import (
	"encoding/hex"
	"testing"
)

func TestGetSolanaAddressFromPrivateKeyBytes(t *testing.T) {
	// The TSM SDK returns ED25519 private keys as raw scalars in big-endian format
	// This is NOT an RFC-8032 seed, but a raw scalar value
	// We need to:
	// 1. Convert from big-endian to little-endian
	// 2. Use scalar multiplication to get the public key
	
	// This is the raw scalar returned by TSM SDK (big-endian)
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	// Expected Solana address for the wallet
	expectedAddr := "CnBUF6yJJvuN7kkjCdPhVKXzCvX8nkMNK32VotpAX19E"
	
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex string: %v", err)
	}

	solanaAddr, err := GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if solanaAddr != expectedAddr {
		t.Errorf("Address mismatch:\n  got:      %s\n  expected: %s", solanaAddr, expectedAddr)
	}
	
	t.Logf("Success: ED25519 raw scalar correctly converted to Solana address")
	t.Logf("  Raw scalar (big-endian): %s", privateKeyHex)
	t.Logf("  Solana address:          %s", solanaAddr)
}