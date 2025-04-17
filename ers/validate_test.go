package ers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
)

type validateTestCase struct {
	Name string

	ERSLabel     []byte
	ERSPublicKey rsa.PublicKey
	PublicKey    []byte
	RecoveryData []byte

	ExpectedValid  bool
	ExpectedErrMsg string
}

func testValidate(t *testing.T, testCases []validateTestCase) {
	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {

			err := ValidateRecoveryData(tc.ERSPublicKey, tc.ERSLabel, tc.PublicKey, tc.RecoveryData)
			if tc.ExpectedValid && err != nil {
				t.Log(err.Error())
				t.FailNow()
			}

			if !tc.ExpectedValid {
				if err == nil {
					t.Log("expected error but got nil")
					t.FailNow()
				} else {
					if !strings.Contains(err.Error(), tc.ExpectedErrMsg) {
						t.Log("Expected '", tc.ExpectedErrMsg, "' but was:", err.Error())
						t.FailNow()
					}
				}
			}

		})
	}
}

func b64toBytes(s string) []byte {
	res, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return res
}

func b64toPublicKey(s string) rsa.PublicKey {
	pubKeyBytes := b64toBytes(s)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		panic(err)
	}
	return *pubKey.(*rsa.PublicKey)
}
