package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha512"

	"github.com/pkg/errors"
)

const (
	pbkdf2Iterations = 3_000_000
	pbkdf2KeyLength  = 32
	saltSize         = 16
)

var hashingFunc = sha512.New

func EncryptData(passwordBytes []byte, contentBytes []byte) ([]byte, error) {
	if passwordBytes == nil {
		return nil, errors.New("password bytes cannot be nil")
	}

	if contentBytes == nil {
		return nil, errors.New("content bytes cannot be nil")
	}

	defer ClearSensitiveBytes(passwordBytes)

	// Generate a random salt for key derivation
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, errors.WithMessage(err, "Error generating salt")
	}

	// Derive encryption key using PBKDF2
	key, err := pbkdf2.Key(hashingFunc, string(passwordBytes), salt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, errors.WithMessage(err, "Error deriving encryption key")
	}
	defer ClearSensitiveBytes(key)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithMessage(err, "Error creating cipher")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithMessage(err, "Error creating GCM")
	}

	// Generate random nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.WithMessage(err, "Error generating nonce")
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

func DecryptData(passwordBytes []byte, encryptedData []byte) ([]byte, error) {
	if passwordBytes == nil {
		return nil, errors.New("password bytes cannot be nil")
	}

	defer ClearSensitiveBytes(passwordBytes)

	// Extract salt (first saltSize bytes)
	if len(encryptedData) < saltSize {
		return nil, errors.New("encrypted data too short: missing salt")
	}
	salt := encryptedData[:saltSize]
	encryptedData = encryptedData[saltSize:]

	// Derive encryption key using PBKDF2 with same parameters as encryption
	key, err := pbkdf2.Key(hashingFunc, string(passwordBytes), salt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, errors.WithMessage(err, "error deriving decryption key")
	}
	defer ClearSensitiveBytes(key)

	// Create AES-256-GCM cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.WithMessage(err, "error creating cipher")
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithMessage(err, "error creating GCM")
	}

	// Extract nonce
	nonceSize := aesgcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("encrypted data too short: missing nonce")
	}
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt the content
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "error decrypting data")
	}

	return plaintext, nil
}

func ClearSensitiveBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
