package utils_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/stretchr/testify/suite"
)

const (
	// Error message fragments for validation
	errPublicKeyNil  = "public key cannot be nil"
	errPrivateKeyNil = "private key cannot be nil"
	errDecryptAESKey = "failed to decrypt AES key"
	errDecodeData    = "failed to decode"
	errWrongLabel    = "wrong label"
	errEmptyData     = "cannot be empty"
	errInvalidStruct = "invalid encrypted data structure"
	errCannotBeNil   = "cannot be nil"
	errBelowMinimum  = "below minimum required"
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

// EncryptionTestSuite tests all encryption/decryption functionality
type EncryptionTestSuite struct {
	suite.Suite
	keys map[int]*rsaKeyPair
}

type rsaKeyPair struct {
	private *rsa.PrivateKey
	public  *rsa.PublicKey
}

// SetupSuite runs once before all tests
func (s *EncryptionTestSuite) SetupSuite() {
	s.keys = make(map[int]*rsaKeyPair)

	// Generate key pairs for different sizes
	keySizes := []int{2048, 3072, 4096}
	for _, size := range keySizes {
		privKey, err := rsa.GenerateKey(rand.Reader, size)
		s.Require().NoError(err)
		s.keys[size] = &rsaKeyPair{
			private: privKey,
			public:  &privKey.PublicKey,
		}
	}
}

// generateTestData creates various test data patterns
func (s *EncryptionTestSuite) generateTestData() []struct {
	name  string
	data  []byte
	label []byte
} {
	return []struct {
		name  string
		data  []byte
		label []byte
	}{
		{"small text", []byte("Hello, World!"), nil},
		{"with label", []byte("Sensitive"), []byte("session-123")},
		{"empty", []byte{}, nil},
		{"binary", []byte{0x00, 0xFF, 0xAB, 0xCD}, []byte("bin")},
		{"unicode", []byte("Hello 世界 🌍"), nil},
	}
}

// TestBasicEncryptDecrypt tests standard encryption/decryption flows
func (s *EncryptionTestSuite) TestBasicEncryptDecrypt() {
	for _, tc := range s.generateTestData() {
		s.Run(tc.name, func() {
			keys := s.keys[2048]

			// Encrypt
			encrypted, err := utils.EncryptWithPublicKey(keys.public, tc.data, tc.label)
			s.NoError(err)
			s.NotNil(encrypted)
			s.NotEqual(tc.data, encrypted)

			// Validate JSON structure
			s.validateJSONStructure(encrypted, tc.label)

			// Decrypt
			decrypted, err := utils.DecryptWithPrivateKey(keys.private, encrypted)
			s.NoError(err)
			s.Equal(tc.data, decrypted)
		})
	}
}

// validateJSONStructure ensures encrypted data has correct JSON format
func (s *EncryptionTestSuite) validateJSONStructure(encrypted, expectedLabel []byte) {
	var encData utils.HybridEncryptedData
	err := json.Unmarshal(encrypted, &encData)
	s.NoError(err, "should be valid JSON")

	s.NotEmpty(encData.EncryptedAESKey, "AES key required")
	s.NotEmpty(encData.EncryptedData, "encrypted data required")
	s.NotEmpty(encData.Nonce, "nonce required")
	s.Equal(expectedLabel, encData.Label)
}

// TestLargeData tests handling of large payloads
func (s *EncryptionTestSuite) TestLargeData() {
	largeData := make([]byte, 100*1024) // 100KB
	_, err := rand.Read(largeData)
	s.NoError(err)

	keys := s.keys[4096]

	encrypted, err := utils.EncryptWithPublicKey(keys.public, largeData, nil)
	s.NoError(err)

	decrypted, err := utils.DecryptWithPrivateKey(keys.private, encrypted)
	s.NoError(err)
	s.Equal(largeData, decrypted)
}

// TestDifferentKeySizes verifies all supported RSA key sizes
func (s *EncryptionTestSuite) TestDifferentKeySizes() {
	testData := []byte("Test data")

	for size, keys := range s.keys {
		s.Run(fmt.Sprintf("%d-bit", size), func() {
			encrypted, err := utils.EncryptWithPublicKey(keys.public, testData, nil)
			s.NoError(err)

			decrypted, err := utils.DecryptWithPrivateKey(keys.private, encrypted)
			s.NoError(err)
			s.Equal(testData, decrypted)
		})
	}
}

// TestErrorCases validates error handling
func (s *EncryptionTestSuite) TestErrorCases() {
	testData := []byte("test data")
	keys2048 := s.keys[2048]
	keys4096 := s.keys[4096]

	// Valid encrypted data for error tests
	encrypted, err := utils.EncryptWithPublicKey(keys2048.public, testData, nil)
	s.NoError(err)

	s.Run("nil public key", func() {
		_, err := utils.EncryptWithPublicKey(nil, testData, nil)
		s.Error(err)
		s.Contains(err.Error(), errPublicKeyNil)
	})

	s.Run("nil private key", func() {
		_, err := utils.DecryptWithPrivateKey(nil, encrypted)
		s.Error(err)
		s.Contains(err.Error(), errPrivateKeyNil)
	})

	s.Run("wrong private key", func() {
		_, err := utils.DecryptWithPrivateKey(keys4096.private, encrypted)
		s.Error(err)
		s.Contains(err.Error(), errDecryptAESKey)
	})

	s.Run("corrupted data", func() {
		corrupted := s.corruptData(encrypted)
		_, err := utils.DecryptWithPrivateKey(keys2048.private, corrupted)
		s.Error(err)
	})

	s.Run("invalid JSON", func() {
		_, err := utils.DecryptWithPrivateKey(keys2048.private, []byte("not json"))
		s.Error(err)
		s.Contains(err.Error(), errDecodeData)
	})

	s.Run("modified label", func() {
		s.testModifiedLabel(keys2048)
	})
}

// corruptData introduces corruption in encrypted data
func (s *EncryptionTestSuite) corruptData(data []byte) []byte {
	corrupted := make([]byte, len(data))
	copy(corrupted, data)

	// Corrupt middle section
	start := len(corrupted) / 2
	end := start + 10
	if end > len(corrupted) {
		end = len(corrupted)
	}

	for i := start; i < end; i++ {
		corrupted[i] ^= 0xFF
	}

	return corrupted
}

// testModifiedLabel verifies label tampering detection
func (s *EncryptionTestSuite) testModifiedLabel(keys *rsaKeyPair) {
	data := []byte("secret")
	correctLabel := []byte("correct")

	encrypted, err := utils.EncryptWithPublicKey(keys.public, data, correctLabel)
	s.NoError(err)

	// Tamper with label
	var encData utils.HybridEncryptedData
	err = json.Unmarshal(encrypted, &encData)
	s.NoError(err)

	encData.Label = []byte("wrong")
	modified, err := json.Marshal(encData)
	s.NoError(err)

	_, err = utils.DecryptWithPrivateKey(keys.private, modified)
	s.Error(err)
	s.Contains(err.Error(), errWrongLabel)
}

// ValidationTestSuite tests validation functions
type ValidationTestSuite struct {
	suite.Suite
	validEncrypted []byte
}

func (s *ValidationTestSuite) SetupSuite() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	s.NoError(err)

	s.validEncrypted, err = utils.EncryptWithPublicKey(&privKey.PublicKey, []byte("test"), nil)
	s.NoError(err)
}

// TestDecodeHybridEncryptedData tests decoding validation
func (s *ValidationTestSuite) TestDecodeHybridEncryptedData() {
	cases := []struct {
		name    string
		data    []byte
		wantErr bool
		errMsg  string
	}{
		{"valid", s.validEncrypted, false, ""},
		{"empty", []byte{}, true, errEmptyData},
		{"invalid JSON", []byte("not json"), true, errInvalidStruct},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			decoded, err := utils.DecodeHybridEncryptedData(tc.data)
			if tc.wantErr {
				s.Error(err)
				if tc.errMsg != "" {
					s.Contains(err.Error(), tc.errMsg)
				}
			} else {
				s.NoError(err)
				s.NotNil(decoded)
			}
		})
	}
}

// TestValidateHybridEncryptedData tests structure validation
func (s *ValidationTestSuite) TestValidateHybridEncryptedData() {
	cases := []struct {
		name    string
		data    []byte
		wantErr bool
		errMsg  string
	}{
		{"valid", s.validEncrypted, false, ""},
		{"invalid JSON", []byte("not json"), true, "failed to decode"},
		{"empty JSON object", []byte("{}"), false, ""},
		{"partial JSON", []byte(`{"encryptedAesKey":`), true, "failed to decode"},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			err := utils.ValidateHybridEncryptedData(tc.data)
			if tc.wantErr {
				s.Error(err)
				if tc.errMsg != "" {
					s.Contains(err.Error(), tc.errMsg)
				}
			} else {
				s.NoError(err)
			}
		})
	}
}

// TestValidateRSAKeySize tests key size requirements
func (s *ValidationTestSuite) TestValidateRSAKeySize() {
	cases := []struct {
		name    string
		keyBits int
		wantErr bool
		errMsg  string
	}{
		{"2048-bit", 2048, false, ""},
		{"4096-bit", 4096, false, ""},
		{"1024-bit", 1024, true, errBelowMinimum},
	}

	for _, tc := range cases {
		s.Run(tc.name, func() {
			key, err := rsa.GenerateKey(rand.Reader, tc.keyBits)
			s.NoError(err)

			err = utils.ValidateRSAKeySize(&key.PublicKey)
			if tc.wantErr {
				s.Error(err)
				if tc.errMsg != "" {
					s.Contains(err.Error(), tc.errMsg)
				}
			} else {
				s.NoError(err)
			}
		})
	}

	s.Run("nil key", func() {
		err := utils.ValidateRSAKeySize(nil)
		s.Error(err)
		s.Contains(err.Error(), errCannotBeNil)
	})
}

// TestSecureZeroBytes tests memory clearing
func (s *ValidationTestSuite) TestSecureZeroBytes() {
	data := []byte("sensitive data")
	originalLen := len(data)

	utils.SecureZeroBytes(data)

	s.Len(data, originalLen)
	for i, b := range data {
		s.Zero(b, "byte %d not zeroed", i)
	}
}

// Benchmarks - no suite needed for simple benchmarks
func BenchmarkEncryptDecrypt4096(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := &privKey.PublicKey
	testData := []byte("Benchmark test data for encryption and decryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := utils.EncryptWithPublicKey(pubKey, testData, nil)
		if err != nil {
			b.Fatal(err)
		}

		_, err = utils.DecryptWithPrivateKey(privKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncryptDecrypt2048(b *testing.B) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	pubKey := &privKey.PublicKey
	testData := []byte("Benchmark test data for encryption and decryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		encrypted, err := utils.EncryptWithPublicKey(pubKey, testData, nil)
		if err != nil {
			b.Fatal(err)
		}

		_, err = utils.DecryptWithPrivateKey(privKey, encrypted)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Test suite runners
func TestEncryptionSuite(t *testing.T) {
	suite.Run(t, new(EncryptionTestSuite))
}

func TestValidationSuite(t *testing.T) {
	suite.Run(t, new(ValidationTestSuite))
}
