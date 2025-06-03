package utils_test

import (
	"testing"

	"github.com/palisadeinc/mpc-recovery/utils"
)

func TestEncryptDecrypt(t *testing.T) {
	// Test encrypting and decrypting a message
	message := "Hello, world!"
	passwordBytes := []byte("password1234")
	ciphertext, err := utils.EncryptData(passwordBytes, []byte(message))
	if err != nil {
		t.Errorf("encrypt failed: %v", err)
	}
	plaintext, err := utils.DecryptData(passwordBytes, ciphertext)
	if err != nil {
		t.Errorf("decrypt failed: %v", err)
	}
	if string(plaintext) != message {
		t.Errorf("decrypted message does not match original")
	}
}

func clear(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
