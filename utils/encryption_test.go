// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils_test

import (
	"testing"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
)

func TestEncryptDecrypt(t *testing.T) {
	tests := []struct {
		name     string
		password string
		message  string
		wantErr  bool
	}{
		{
			name:     "valid message encryption and decryption",
			password: "password1234",
			message:  "Hello, world!",
			wantErr:  false,
		},
		{
			name:     "empty message",
			password: "password1234",
			message:  "",
			wantErr:  false,
		},
		{
			name:     "long message",
			password: "password1234",
			message:  "The quick brown fox jumps over the lazy dog. This is a longer message to test encryption.",
			wantErr:  false,
		},
		{
			name:     "special characters in message",
			password: "password1234",
			message:  "!@#$%^&*()_+-=[]{}|;:',.<>?/",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := utils.EncryptData([]byte(tt.password), []byte(tt.message))
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			plaintext, err := utils.DecryptData([]byte(tt.password), ciphertext)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptData() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if string(plaintext) != tt.message {
				t.Errorf("DecryptData() = %q, want %q", string(plaintext), tt.message)
			}
		})
	}
}

func TestHasEncryptionHeader(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid header",
			data:     []byte("PKE1" + "some encrypted content"),
			expected: true,
		},
		{
			name:     "plain hex string starting with 30",
			data:     []byte("308204be020100"),
			expected: false,
		},
		{
			name:     "empty data",
			data:     []byte{},
			expected: false,
		},
		{
			name:     "data too short",
			data:     []byte("PKE"),
			expected: false,
		},
		{
			name:     "wrong header",
			data:     []byte("XXXX" + "content"),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := utils.HasEncryptionHeader(tt.data)
			if result != tt.expected {
				t.Errorf("HasEncryptionHeader(%q) = %v, want %v", tt.data, result, tt.expected)
			}
		})
	}
}

func TestEncryptDecryptWithHeader(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		password string
		wantErr  bool
	}{
		{
			name:     "valid hex string encryption with header",
			message:  "308204be020100300d06092a864886f70d0101010500",
			password: "testPassword123!",
			wantErr:  false,
		},
		{
			name:     "empty message with header",
			message:  "",
			password: "testPassword123!",
			wantErr:  false,
		},
		{
			name:     "long message with header",
			message:  "308204be020100300d06092a864886f70d0101010500308204be020100300d06092a864886f70d0101010500",
			password: "testPassword123!",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt with header
			encrypted, err := utils.EncryptWithHeader([]byte(tt.password), []byte(tt.message))
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptWithHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify header is present
			if !utils.HasEncryptionHeader(encrypted) {
				t.Error("encrypted data should have header")
			}

			// Verify it starts with PKE1
			if string(encrypted[:4]) != "PKE1" {
				t.Errorf("encrypted data should start with PKE1, got %q", string(encrypted[:4]))
			}

			// Decrypt with header
			decrypted, err := utils.DecryptWithHeader([]byte(tt.password), encrypted)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if string(decrypted) != tt.message {
				t.Errorf("DecryptWithHeader() = %q, want %q", string(decrypted), tt.message)
			}
		})
	}
}

func TestDecryptWithHeader_ErrorCases(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() ([]byte, []byte) // returns (data, password)
		decryptPass string
		wantErr     bool
	}{
		{
			name: "wrong password",
			setupFunc: func() ([]byte, []byte) {
				message := "secret data"
				password := []byte("correctPassword")
				encrypted, err := utils.EncryptWithHeader(password, []byte(message))
				if err != nil {
					t.Fatalf("EncryptWithHeader failed: %v", err)
				}
				return encrypted, []byte("wrongPassword")
			},
			wantErr: true,
		},
		{
			name: "missing header",
			setupFunc: func() ([]byte, []byte) {
				plainEncrypted, err := utils.EncryptData([]byte("password"), []byte("content"))
				if err != nil {
					t.Fatalf("EncryptData failed: %v", err)
				}
				return plainEncrypted, []byte("password")
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, password := tt.setupFunc()
			_, err := utils.DecryptWithHeader(password, data)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithHeader() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Benchmark tests for performance-critical encryption operations

// BenchmarkEncryptData measures the performance of the EncryptData function
func BenchmarkEncryptData(b *testing.B) {
	data := []byte("test data to encrypt - this is a sample message for benchmarking")
	password := []byte("testpassword123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = utils.EncryptData(password, data) //nolint:errcheck // benchmark
	}
}

// BenchmarkDecryptData measures the performance of the DecryptData function
func BenchmarkDecryptData(b *testing.B) {
	data := []byte("test data to encrypt - this is a sample message for benchmarking")
	password := []byte("testpassword123")

	// Pre-encrypt the data once
	encrypted, err := utils.EncryptData(password, data)
	if err != nil {
		b.Fatalf("Failed to encrypt data for benchmark: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = utils.DecryptData(password, encrypted) //nolint:errcheck // benchmark
	}
}

// BenchmarkPBKDF2 measures the performance of PBKDF2 key derivation
// Note: PBKDF2 is intentionally slow for security reasons (3 million iterations)
func BenchmarkPBKDF2(b *testing.B) {
	// This benchmark demonstrates the cost of key derivation
	// which is the most time-consuming part of encryption/decryption
	data := []byte("test data")
	password := []byte("testpassword123")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = utils.EncryptData(password, data) //nolint:errcheck // benchmark
	}
}

// FuzzDecryptData tests decryption with random/malformed input
// This fuzz test ensures DecryptData doesn't panic on malformed encrypted data
func FuzzDecryptData(f *testing.F) {
	// Add seed corpus with various malformed encrypted data
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0x01, 0x02, 0x03})
	f.Add([]byte("short"))
	f.Add([]byte("this is not encrypted data at all"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Add([]byte("PKE1" + "malformed"))
	f.Add(make([]byte, 16)) // 16 zero bytes (salt size)
	f.Add(make([]byte, 32)) // 32 zero bytes
	f.Add(make([]byte, 100))
	f.Add([]byte("a" + string(make([]byte, 1000))))

	f.Fuzz(func(_ *testing.T, encryptedData []byte) {
		// Should not panic - DecryptData should handle any input gracefully
		// It's expected to return an error for malformed data
		_, _ = utils.DecryptData([]byte("password"), encryptedData) //nolint:errcheck // fuzz test
	})
}
