package utils_test

import (
	"testing"

	"github.com/palisadeinc/mpc-recovery/utils"
)

func TestEncryptDecrypt(t *testing.T) {
	// Test encrypting and decrypting a message
	message := "Hello, world!"
	ciphertext, err := utils.EncryptData([]byte("password1234"), []byte(message))
	if err != nil {
		t.Errorf("encrypt failed: %v", err)
	}
	plaintext, err := utils.DecryptData([]byte("password1234"), ciphertext)
	if err != nil {
		t.Errorf("decrypt failed: %v", err)
	}
	if string(plaintext) != message {
		t.Errorf("decrypted message does not match original")
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
	message := "308204be020100300d06092a864886f70d0101010500"
	password := []byte("testPassword123!")

	// Encrypt with header
	encrypted, err := utils.EncryptWithHeader(password, []byte(message))
	if err != nil {
		t.Fatalf("EncryptWithHeader failed: %v", err)
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
	decrypted, err := utils.DecryptWithHeader([]byte("testPassword123!"), encrypted)
	if err != nil {
		t.Fatalf("DecryptWithHeader failed: %v", err)
	}

	if string(decrypted) != message {
		t.Errorf("decrypted message does not match original: got %q, want %q", string(decrypted), message)
	}
}

func TestDecryptWithHeader_WrongPassword(t *testing.T) {
	message := "secret data"
	password := []byte("correctPassword")

	encrypted, err := utils.EncryptWithHeader(password, []byte(message))
	if err != nil {
		t.Fatalf("EncryptWithHeader failed: %v", err)
	}

	_, err = utils.DecryptWithHeader([]byte("wrongPassword"), encrypted)
	if err == nil {
		t.Error("DecryptWithHeader should fail with wrong password")
	}
}

func TestDecryptWithHeader_MissingHeader(t *testing.T) {
	// Data without header (just encrypted content)
	plainEncrypted, err := utils.EncryptData([]byte("password"), []byte("content"))
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	_, err = utils.DecryptWithHeader([]byte("password"), plainEncrypted)
	if err == nil {
		t.Error("DecryptWithHeader should fail without header")
	}
}
