package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/json"
	"fmt"

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

// HybridEncryptedData contains all components needed for decryption
type HybridEncryptedData struct {
	EncryptedAESKey []byte `json:"encryptedAesKey"`
	EncryptedData   []byte `json:"encryptedData"`
	Nonce           []byte `json:"nonce"`
	Label           []byte `json:"label,omitempty"`
}

// EncryptWithPublicKey encrypts data with an optional OAEP label
func EncryptWithPublicKey(rsaPubKey *rsa.PublicKey, data, label []byte) ([]byte, error) {
	if rsaPubKey == nil {
		return nil, errors.New("public key cannot be nil")
	}
	// Generate a random 256-bit AES key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, errors.WithMessage(err, "failed to generate AES key")
	}

	// Encrypt the AES key with RSA-OAEP, INCLUDING THE LABEL
	encryptedAESKey, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		rsaPubKey,
		aesKey,
		label,
	)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to encrypt AES key")
	}

	// Create AES-GCM cipher for the actual data
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create GCM")
	}

	// Generate nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errors.WithMessage(err, "failed to generate nonce")
	}

	// Encrypt the actual data with AES-GCM
	encryptedData := aesGCM.Seal(nil, nonce, data, nil)

	h := HybridEncryptedData{
		EncryptedAESKey: encryptedAESKey,
		EncryptedData:   encryptedData,
		Nonce:           nonce,
		Label:           label,
	}

	jsonData, err := json.Marshal(h)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to encode encrypted data")
	}

	return jsonData, nil
}

// DecryptWithPrivateKey decrypts data with label verification
func DecryptWithPrivateKey(privateKey *rsa.PrivateKey, encryptedData []byte) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key cannot be nil")
	}

	var encData HybridEncryptedData
	if err := json.Unmarshal(encryptedData, &encData); err != nil {
		return nil, errors.WithMessage(err, "failed to decode encrypted data")
	}

	// Decrypt the AES key with RSA-OAEP, using the same label
	aesKey, err := rsa.DecryptOAEP(
		sha256.New(),
		nil, // as per go doc
		privateKey,
		encData.EncryptedAESKey,
		encData.Label,
	)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decrypt AES key (wrong label?)")
	}

	// Create AES-GCM cipher
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create AES cipher")
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to create GCM")
	}

	// Decrypt the data with AES-GCM
	decryptedData, err := aesGCM.Open(nil, encData.Nonce, encData.EncryptedData, nil)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to decrypt data")
	}

	// Ensure we return an empty slice rather than nil for empty data
	if decryptedData == nil {
		return []byte{}, nil
	}

	return decryptedData, nil
}

// DecodeHybridEncryptedData decodes and validates the structure of encrypted data
// without performing decryption. This is useful for validation before attempting decryption.
func DecodeHybridEncryptedData(encryptedData []byte) (*HybridEncryptedData, error) {
	if len(encryptedData) == 0 {
		return nil, errors.New("encrypted data cannot be empty")
	}

	var encData HybridEncryptedData
	if err := json.Unmarshal(encryptedData, &encData); err != nil {
		return nil, errors.WithMessage(err, "invalid encrypted data structure")
	}

	return &encData, nil
}

// ValidateHybridEncryptedData validates if encryptedBytes is in the right format
func ValidateHybridEncryptedData(encryptedBytes []byte) error {
	var encData HybridEncryptedData
	if err := json.Unmarshal(encryptedBytes, &encData); err != nil {
		return errors.WithMessage(err, "failed to decode encrypted data")
	}
	return nil
}

// ValidateRSAKeySize validates that an RSA key meets minimum security requirements
func ValidateRSAKeySize(key *rsa.PublicKey) error {
	if key == nil {
		return errors.New("RSA key cannot be nil")
	}

	// Minimum 2048-bit keys for security
	const minKeyBits = 2048
	keyBits := key.N.BitLen()

	if keyBits < minKeyBits {
		return fmt.Errorf("RSA key size %d bits is below minimum required %d bits",
			keyBits, minKeyBits)
	}

	return nil
}

// SecureZeroBytes overwrites the byte slice with zeros
// This helps protect sensitive data in memory, though it's not guaranteed
// due to potential compiler optimizations and garbage collection
func SecureZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
