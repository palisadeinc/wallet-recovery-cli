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
