package ers

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"testing"
)

type recoverTestCase struct {
	PlayerCount     int
	Threshold       int
	SharingType     string
	Curve           string
	Label           string
	ERSPrivateKey   *rsa.PrivateKey
	PrivateKey      []byte
	MasterChainCode []byte
	RecoveryData    []byte
}

func testRecovery(t *testing.T, testCases []recoverTestCase) {
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("curve=%s,sharing=%s,n=%d,t=%d", tc.Curve, tc.SharingType, tc.PlayerCount, tc.Threshold), func(t *testing.T) {

			rsaDecryptor := NewRSADecryptor(tc.ERSPrivateKey)
			ellipticCurve, privateKey, masterChainCode, err := RecoverPrivateKey(rsaDecryptor, []byte(tc.Label), tc.RecoveryData, nil)
			requireNoError(t, err)
			requireTrue(t, bytes.Equal(privateKey, tc.PrivateKey))
			requireTrue(t, bytes.Equal(masterChainCode, tc.MasterChainCode))

			if ellipticCurve != "ED-25519" {
				ecdsaPrivateKey, err := PrivateKeyToECDSAPrivateKey(ellipticCurve, privateKey)
				requireNoError(t, err)
				requireTrue(t, ecdsaPrivateKey != nil)

				ecPrivateKey, err := PrivateKeyToASN1PrivateKey(ellipticCurve, privateKey)
				requireNoError(t, err)
				requireTrue(t, len(ecPrivateKey) > 0)
			}
		})
	}
}

func decodeTestData(playerCount, threshold int, sharingType, curve, recoveryData, label, ersPrivateKey, privateKey, masterChainCode string) recoverTestCase {
	decodedERSPrivateKey, err := base64.StdEncoding.DecodeString(ersPrivateKey)
	if err != nil {
		panic(err)
	}
	ersPKCS8PrivateKey, err := x509.ParsePKCS8PrivateKey(decodedERSPrivateKey)
	if err != nil {
		panic(err)
	}
	ersRSAPrivateKey, isRSAPrivateKey := ersPKCS8PrivateKey.(*rsa.PrivateKey)
	if !isRSAPrivateKey {
		panic(fmt.Errorf("only RSA private keys are supported"))
	}
	decodedRecoveryData, err := base64.StdEncoding.DecodeString(recoveryData)
	if err != nil {
		panic(err)
	}
	decodedPrivateKey, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		panic(err)
	}
	decodedMasterChainCode, err := base64.StdEncoding.DecodeString(masterChainCode)
	if err != nil {
		panic(err)
	}

	return recoverTestCase{
		PlayerCount:     playerCount,
		Threshold:       threshold,
		SharingType:     sharingType,
		Curve:           curve,
		Label:           label,
		ERSPrivateKey:   ersRSAPrivateKey,
		PrivateKey:      decodedPrivateKey,
		MasterChainCode: decodedMasterChainCode,
		RecoveryData:    decodedRecoveryData,
	}
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Logf(err.Error())
		t.FailNow()
	}
}

func requireTrue(t *testing.T, b bool) {
	t.Helper()
	if !b {
		t.Logf("expected true")
		t.FailNow()
	}
}
