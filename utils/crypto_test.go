// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"encoding/hex"
	"testing"
)

func TestGetSolanaAddressFromPrivateKeyBytes(t *testing.T) {
	tests := []struct {
		name          string
		privateKeyHex string
		expectedAddr  string
		wantErr       bool
	}{
		{
			name:          "valid ED25519 raw scalar",
			privateKeyHex: "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb",
			expectedAddr:  "CnBUF6yJJvuN7kkjCdPhVKXzCvX8nkMNK32VotpAX19E",
			wantErr:       false,
		},
		{
			name:          "invalid key size (too long)",
			privateKeyHex: "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb0000",
			expectedAddr:  "",
			wantErr:       true,
		},
		{
			name:          "invalid key size (too short)",
			privateKeyHex: "0102030405060708090a0b0c0d0e0f",
			expectedAddr:  "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKeyBytes, err := hex.DecodeString(tt.privateKeyHex)
			if err != nil {
				t.Fatalf("Failed to decode hex string: %v", err)
			}

			solanaAddr, err := GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetSolanaAddressFromPrivateKeyBytes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if solanaAddr != tt.expectedAddr {
				t.Errorf("GetSolanaAddressFromPrivateKeyBytes() = %s, want %s", solanaAddr, tt.expectedAddr)
			}
		})
	}
}

// Benchmark tests for performance-critical cryptographic operations

// BenchmarkGetSolanaAddress measures the performance of Solana address derivation
func BenchmarkGetSolanaAddress(b *testing.B) {
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		b.Fatalf("Failed to decode hex string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes) //nolint:errcheck // benchmark
	}
}

// BenchmarkGetEthereumAddress measures the performance of Ethereum address derivation
func BenchmarkGetEthereumAddress(b *testing.B) {
	// Using a valid 32-byte private key for Ethereum
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		b.Fatalf("Failed to decode hex string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes) //nolint:errcheck // benchmark
	}
}

// BenchmarkGetXRPAddress measures the performance of XRP address derivation
func BenchmarkGetXRPAddress(b *testing.B) {
	// Using a valid 32-byte private key for XRP (SECP256K1)
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		b.Fatalf("Failed to decode hex string: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetXRPAddressFromPrivateKeyBytes(privateKeyBytes) //nolint:errcheck // benchmark
	}
}
