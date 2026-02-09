// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
)

// TestGenerateCommandE2EUnencrypted tests the end-to-end flow of generating an unencrypted keypair
func TestGenerateCommandE2EUnencrypted(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "private.der")
	publicKeyPath := filepath.Join(tempDir, "public.der")

	// Generate a keypair directly using the crypto functions
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert private key to DER format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	defer utils.ClearSensitiveBytes(privateKeyDER)

	// Convert to hex string
	privateKeyHex := hex.EncodeToString(privateKeyDER)

	// Extract public key and convert to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKeyDER)

	// Write private key to file
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}

	// Write public key to file
	publicKeyFile, err := os.OpenFile(publicKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()

	if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Errorf("Private key file was not created: %v", err)
	}
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Errorf("Public key file was not created: %v", err)
	}

	// Verify file permissions
	privateKeyInfo, err := os.Stat(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to stat private key file: %v", err)
	}
	if privateKeyInfo.Mode().Perm() != 0o400 {
		t.Errorf("Private key file permissions = %o, want 0o400", privateKeyInfo.Mode().Perm())
	}

	// Read and validate public key
	publicKeyBytes, err := utils.OpenReadOnlyFile(publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read public key file: %v", err)
	}
	defer utils.ClearSensitiveBytes(publicKeyBytes)

	// Verify public key is valid PKIX DER format
	publicKeyHexRead := string(publicKeyBytes)
	publicKeyDERRead, err := hex.DecodeString(publicKeyHexRead)
	if err != nil {
		t.Errorf("Public key is not valid hex: %v", err)
	}

	publicKeyParsed, err := x509.ParsePKIXPublicKey(publicKeyDERRead)
	if err != nil {
		t.Errorf("Public key is not valid PKIX DER format: %v", err)
	}

	// Verify it's an RSA key
	rsaPublicKey, ok := publicKeyParsed.(*rsa.PublicKey)
	if !ok {
		t.Error("Public key is not an RSA key")
	}

	// Verify RSA-4096
	if rsaPublicKey.N.BitLen() != 4096 {
		t.Errorf("RSA key size = %d bits, want 4096", rsaPublicKey.N.BitLen())
	}

	// Read and validate private key
	privateKeyBytes, err := utils.OpenReadOnlyFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}
	defer utils.ClearSensitiveBytes(privateKeyBytes)

	// Verify private key is valid hex-encoded RSA key
	privateKeyHexRead := string(privateKeyBytes)
	privateKeyDERRead, err := hex.DecodeString(privateKeyHexRead)
	if err != nil {
		t.Errorf("Private key is not valid hex: %v", err)
	}
	defer utils.ClearSensitiveBytes(privateKeyDERRead)

	// Try to parse as PKCS1
	privateKeyParsed, err := x509.ParsePKCS1PrivateKey(privateKeyDERRead)
	if err != nil {
		t.Errorf("Private key is not valid RSA key: %v", err)
	}

	// Verify RSA-4096
	if privateKeyParsed.N.BitLen() != 4096 {
		t.Errorf("RSA private key size = %d bits, want 4096", privateKeyParsed.N.BitLen())
	}
}

// TestGenerateCommandE2EWithEncryption tests the end-to-end flow of generating an encrypted keypair
func TestGenerateCommandE2EWithEncryption(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "private.der")
	publicKeyPath := filepath.Join(tempDir, "public.der")

	// Generate a keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert private key to DER format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	defer utils.ClearSensitiveBytes(privateKeyDER)

	// Convert to hex string
	privateKeyHex := hex.EncodeToString(privateKeyDER)

	// Extract public key and convert to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKeyDER)

	// Encrypt the private key
	password := []byte("testPassword123!")
	passwordCopy := make([]byte, len(password))
	copy(passwordCopy, password)
	encryptedPrivateKey, err := utils.EncryptWithHeader(passwordCopy, []byte(privateKeyHex))
	if err != nil {
		t.Fatalf("Failed to encrypt private key: %v", err)
	}

	// Write encrypted private key to file
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if _, err := privateKeyFile.Write(encryptedPrivateKey); err != nil {
		t.Fatalf("Failed to write encrypted private key: %v", err)
	}

	// Write public key to file
	publicKeyFile, err := os.OpenFile(publicKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()

	if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	// Verify files exist
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Errorf("Private key file was not created: %v", err)
	}
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Errorf("Public key file was not created: %v", err)
	}

	// Read and verify encrypted private key has encryption header
	encryptedKeyBytes, err := utils.OpenReadOnlyFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read encrypted private key file: %v", err)
	}
	defer utils.ClearSensitiveBytes(encryptedKeyBytes)

	if !utils.HasEncryptionHeader(encryptedKeyBytes) {
		t.Error("Encrypted private key should have encryption header but doesn't")
	}

	// Verify the header is "PKE1"
	if string(encryptedKeyBytes[:4]) != "PKE1" {
		t.Errorf("Encryption header = %q, want %q", string(encryptedKeyBytes[:4]), "PKE1")
	}

	// Verify we can decrypt with correct password
	decryptedBytes, err := utils.DecryptWithHeader(password, encryptedKeyBytes)
	if err != nil {
		t.Errorf("Failed to decrypt with correct password: %v", err)
	}
	defer utils.ClearSensitiveBytes(decryptedBytes)

	// Verify decrypted content matches original hex
	if string(decryptedBytes) != privateKeyHex {
		t.Error("Decrypted private key does not match original")
	}

	// Verify decryption fails with wrong password
	wrongPassword := []byte("wrongPassword123!")
	_, err = utils.DecryptWithHeader(wrongPassword, encryptedKeyBytes)
	if err == nil {
		t.Error("Decryption should fail with wrong password but didn't")
	}
}

// TestValidateKeyCommandE2EUnencrypted tests the validate-key command with unencrypted keys
func TestValidateKeyCommandE2EUnencrypted(t *testing.T) {
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "private.der")
	publicKeyPath := filepath.Join(tempDir, "public.der")

	// Generate a keypair
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Convert private key to DER format
	privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
	defer utils.ClearSensitiveBytes(privateKeyDER)

	// Convert to hex string
	privateKeyHex := hex.EncodeToString(privateKeyDER)

	// Extract public key and convert to DER format
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}
	publicKeyHex := hex.EncodeToString(publicKeyDER)

	// Write private key to file
	privateKeyFile, err := os.OpenFile(privateKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
		t.Fatalf("Failed to write private key: %v", err)
	}

	// Write public key to file
	publicKeyFile, err := os.OpenFile(publicKeyPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
	if err != nil {
		t.Fatalf("Failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()

	if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
		t.Fatalf("Failed to write public key: %v", err)
	}

	// Verify the unencrypted private key file is valid
	privateKeyBytes, err := utils.OpenReadOnlyFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read private key file: %v", err)
	}
	defer utils.ClearSensitiveBytes(privateKeyBytes)

	// Verify it does NOT have encryption header
	if utils.HasEncryptionHeader(privateKeyBytes) {
		t.Error("Unencrypted private key should not have encryption header")
	}

	// Verify it's a valid hex-encoded RSA key
	privateKeyHexRead := string(privateKeyBytes)
	privateKeyDERRead, err := hex.DecodeString(privateKeyHexRead)
	if err != nil {
		t.Errorf("Private key is not valid hex: %v", err)
	}
	defer utils.ClearSensitiveBytes(privateKeyDERRead)

	// Parse as PKCS1
	privateKeyParsed, err := x509.ParsePKCS1PrivateKey(privateKeyDERRead)
	if err != nil {
		t.Errorf("Private key is not valid RSA key: %v", err)
	}

	// Verify RSA-4096
	if privateKeyParsed.N.BitLen() != 4096 {
		t.Errorf("RSA private key size = %d bits, want 4096", privateKeyParsed.N.BitLen())
	}
}
