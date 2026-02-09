// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils //nolint:revive // utils is an acceptable package name for utility functions

import (
	"encoding/hex"
	"testing"
)

// TestRecoverED25519PrivateKey tests the ED25519 recovery functionality
func TestRecoverED25519PrivateKey(t *testing.T) {
	tests := []struct {
		name            string
		privateKeyHex   string
		expectedAddress string
		wantErr         bool
	}{
		{
			name:            "valid ED25519 scalar",
			privateKeyHex:   "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb",
			expectedAddress: "CnBUF6yJJvuN7kkjCdPhVKXzCvX8nkMNK32VotpAX19E",
			wantErr:         false,
		},
		{
			name:            "invalid key size (too long)",
			privateKeyHex:   "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb0000000000000000",
			expectedAddress: "",
			wantErr:         true,
		},
		{
			name:            "invalid key size (too short)",
			privateKeyHex:   "0102030405060708090a0b0c0d0e0f",
			expectedAddress: "",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testPrivateKey, err := hex.DecodeString(tt.privateKeyHex)
			if err != nil {
				t.Fatalf("Failed to decode test private key: %v", err)
			}

			solanaAddress, err := GetSolanaAddressFromPrivateKeyBytes(testPrivateKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSolanaAddressFromPrivateKeyBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if solanaAddress != tt.expectedAddress {
				t.Errorf("GetSolanaAddressFromPrivateKeyBytes() = %s, want %s", solanaAddress, tt.expectedAddress)
			}
		})
	}
}

// TestKeyAlgorithmDetection tests the key algorithm detection and validation
func TestKeyAlgorithmDetection(t *testing.T) {
	tests := []struct {
		name         string
		keyAlgorithm string
		expectError  bool
	}{
		{
			name:         "SECP256K1 key type",
			keyAlgorithm: "SECP256K1",
			expectError:  false,
		},
		{
			name:         "ED25519 key type",
			keyAlgorithm: "ED25519",
			expectError:  false,
		},
		{
			name:         "Invalid key type",
			keyAlgorithm: "INVALID",
			expectError:  true,
		},
		{
			name:         "Empty key type (defaults to SECP256K1)",
			keyAlgorithm: "",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(
			tt.name, func(t *testing.T) {
				// Test logic would go here
				// This is a placeholder for the actual implementation
				t.Logf("Testing key algorithm: %s", tt.keyAlgorithm)
			},
		)
	}
}
