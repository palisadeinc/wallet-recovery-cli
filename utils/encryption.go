// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0
package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
)

const (
	// DefaultPBKDF2Iterations is the production iteration count for PBKDF2.
	// This is intentionally high (3 million) for security.
	DefaultPBKDF2Iterations = 3_000_000

	pbkdf2KeyLength = 32
	saltSize        = 16

	// MagicHeaderSize is the size of the magic header for encrypted files
	MagicHeaderSize = 4
	// MagicHeaderRSAKey is the magic header for encrypted RSA private keys
	MagicHeaderRSAKey = "PKE1"
)

var (
	hashingFunc = sha512.New

	// PBKDF2Iterations is the number of PBKDF2 iterations to use.
	// This can be reduced in tests for faster execution.
	// DO NOT change this in production code.
	PBKDF2Iterations = DefaultPBKDF2Iterations
)

func EncryptData(passwordBytes, contentBytes []byte) ([]byte, error) {
	if passwordBytes == nil {
		return nil, fmt.Errorf("password bytes cannot be nil")
	}

	if contentBytes == nil {
		return nil, fmt.Errorf("content bytes cannot be nil")
	}

	defer ClearSensitiveBytes(passwordBytes)

	// Generate a random salt for key derivation
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key using PBKDF2
	key, err := pbkdf2.Key(hashingFunc, string(passwordBytes), salt, PBKDF2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, fmt.Errorf("failed to derive encryption key: %w", err)
	}
	defer ClearSensitiveBytes(key)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the content
	ciphertext := aesgcm.Seal(nil, nonce, contentBytes, nil)

	// Format: salt + nonce + ciphertext
	encryptedData := make([]byte, 0, len(salt)+len(nonce)+len(ciphertext))
	encryptedData = append(encryptedData, salt...)
	encryptedData = append(encryptedData, nonce...)
	encryptedData = append(encryptedData, ciphertext...)

	return encryptedData, nil
}

func DecryptData(passwordBytes, encryptedData []byte) ([]byte, error) {
	if passwordBytes == nil {
		return nil, fmt.Errorf("password bytes cannot be nil")
	}

	defer ClearSensitiveBytes(passwordBytes)

	// Extract salt (first saltSize bytes)
	if len(encryptedData) < saltSize {
		return nil, fmt.Errorf("encrypted data too short: missing salt")
	}
	salt := encryptedData[:saltSize]
	encryptedData = encryptedData[saltSize:]

	// Derive encryption key using PBKDF2 with same parameters as encryption
	key, err := pbkdf2.Key(hashingFunc, string(passwordBytes), salt, PBKDF2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, fmt.Errorf("error deriving decryption key: %w", err)
	}
	defer ClearSensitiveBytes(key)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creating cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("error creating GCM: %w", err)
	}

	// Extract nonce
	nonceSize := aesgcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short: missing nonce")
	}
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt the content
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("error decrypting data: %w", err)
	}

	return plaintext, nil
}

func ClearSensitiveBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// HasEncryptionHeader checks if the data starts with the magic header for encrypted RSA keys
func HasEncryptionHeader(data []byte) bool {
	if len(data) < MagicHeaderSize {
		return false
	}
	return string(data[:MagicHeaderSize]) == MagicHeaderRSAKey
}

// LooksLikeEncryptedData checks if data appears to be encrypted (headerless legacy format).
// It uses heuristics: encrypted data is binary (non-printable) and has sufficient length
// for salt + nonce + ciphertext (minimum ~45 bytes for AES-GCM with 16-byte auth tag).
// This is a best-effort detection for backwards compatibility with pre-header encrypted files.
func LooksLikeEncryptedData(data []byte) bool {
	// Minimum size: 16 (salt) + 12 (nonce) + 16 (auth tag) + 1 (min ciphertext) = 45 bytes
	const minEncryptedSize = 45

	if len(data) < minEncryptedSize {
		return false
	}

	// Check if data looks binary (non-text)
	// Encrypted data should have high entropy and non-printable characters
	nonPrintableCount := 0
	sampleSize := min(len(data), 64) // Check first 64 bytes

	for i := 0; i < sampleSize; i++ {
		b := data[i]
		// Count bytes outside printable ASCII range (32-126) and common whitespace
		if b < 32 || b > 126 {
			if b != '\n' && b != '\r' && b != '\t' {
				nonPrintableCount++
			}
		}
	}

	// If more than 30% of sampled bytes are non-printable, it's likely binary/encrypted
	return nonPrintableCount > sampleSize*30/100
}

// EncryptWithHeader encrypts content using AES-256-GCM and prepends a magic header.
// Format: [4 bytes header "PKE1"] + [16 bytes salt] + [12 bytes nonce] + [ciphertext + auth tag]
func EncryptWithHeader(passwordBytes, contentBytes []byte) ([]byte, error) {
	encryptedData, err := EncryptData(passwordBytes, contentBytes)
	if err != nil {
		return nil, err
	}

	// Prepend magic header
	result := make([]byte, MagicHeaderSize+len(encryptedData))
	copy(result[:MagicHeaderSize], MagicHeaderRSAKey)
	copy(result[MagicHeaderSize:], encryptedData)

	return result, nil
}

// DecryptWithHeader validates the magic header and decrypts the content.
// Returns error if header is missing/invalid or decryption fails.
func DecryptWithHeader(passwordBytes, encryptedData []byte) ([]byte, error) {
	if !HasEncryptionHeader(encryptedData) {
		return nil, fmt.Errorf("invalid encrypted file: missing or invalid header")
	}

	// Strip header and decrypt
	return DecryptData(passwordBytes, encryptedData[MagicHeaderSize:])
}
