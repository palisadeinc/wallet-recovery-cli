package tsm

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/partialresults/partialrsa"
)

// RSAFinalizeSignaturePKCS1v15 constructs an RSASSA-PKCS1-V1_5-SIGN signature from RSA PKCS #1 v1.5. If hashed is
// specified then the resulting signature is verified before returning.
func RSAFinalizeSignaturePKCS1v15(hashFunction string, hashed []byte, partialSignatures [][]byte) (signature []byte, err error) {
	h, err := getHashFunction(hashFunction)
	if err != nil {
		return nil, err
	}
	partialResults, err := rsaParsePartialResults(partialSignatures)
	if err != nil {
		return nil, err
	}
	return partialrsa.FinalizeRSASignaturePKCS1v15(partialResults, h, hashed)
}

// RSAFinalizeSignaturePSS constructs an RSASSA-PSS signature. If digest is specified then the resulting signature
// is verified before returning.
func RSAFinalizeSignaturePSS(hashFunction string, digest []byte, partialSignatures [][]byte) (signature []byte, err error) {
	h, err := getHashFunction(hashFunction)
	if err != nil {
		return nil, err
	}
	partialResults, err := rsaParsePartialResults(partialSignatures)
	if err != nil {
		return nil, err
	}
	return partialrsa.FinalizeRSASignaturePSS(partialResults, h, digest)
}

// RSAFinalizeDecryptionPKCS1v15 decrypts a plaintext using RSA and the padding scheme from PKCS #1 v1.5.
func RSAFinalizeDecryptionPKCS1v15(partialSignatures [][]byte) (plaintext []byte, err error) {
	partialResults, err := rsaParsePartialResults(partialSignatures)
	if err != nil {
		return nil, err
	}
	return partialrsa.FinalizeRSADecryptionPKCS1v15(partialResults)
}

// RSAFinalizeDecryptionOAEP decrypts a plaintext using RSA-OAEP.
func RSAFinalizeDecryptionOAEP(hashFunction string, label []byte, partialSignatures [][]byte) (plaintext []byte, err error) {
	h, err := getHashFunction(hashFunction)
	if err != nil {
		return nil, err
	}
	partialResults, err := rsaParsePartialResults(partialSignatures)
	if err != nil {
		return nil, err
	}
	return partialrsa.FinalizeRSADecryptionOAEP(partialResults, h.New(), label)
}

// RSAFinalizeDecryptionRaw performs raw RSA decryption.
func RSAFinalizeDecryptionRaw(partialSignatures [][]byte) (plaintext []byte, err error) {
	partialResults, err := rsaParsePartialResults(partialSignatures)
	if err != nil {
		return nil, err
	}
	return partialrsa.FinalizeRSADecryptionRaw(partialResults)
}

// RSAVerifySignaturePKCS1v15 verifies the SASSA-PKCS1-V1_5-SIGN signature from RSA PKCS #1 v1.5 and returns an error if
// it is not valid. The pkixPublicKey is the ASN.1 DER encoded SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
func RSAVerifySignaturePKCS1v15(pkixPublicKey []byte, hashFunction string, hashed, signature []byte) error {
	publicKey, err := x509.ParsePKIXPublicKey(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("verify signature: unable to parse public key:: %s", err)
	}
	rsaPublicKey, isRSAPublicKey := publicKey.(*rsa.PublicKey)
	if !isRSAPublicKey {
		return fmt.Errorf("verify signature: not an RSA public key")
	}
	h, err := getHashFunction(hashFunction)
	if err != nil {
		return err
	}
	if err = rsa.VerifyPKCS1v15(rsaPublicKey, h, hashed, signature); err != nil {
		return fmt.Errorf("verify signature: %s", err)
	}
	return nil
}

// RSAVerifySignaturePSS verifies the RSASSA-PSS signature and returns an error if it is not valid. The
// pkixPublicKey is the ASN.1 DER encoded SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
func RSAVerifySignaturePSS(pkixPublicKey []byte, hashFunction string, hashed, signature []byte) error {
	publicKey, err := x509.ParsePKIXPublicKey(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("verify signature: unable to parse public key:: %s", err)
	}
	rsaPublicKey, isRSAPublicKey := publicKey.(*rsa.PublicKey)
	if !isRSAPublicKey {
		return fmt.Errorf("verify signature: not an RSA public key")
	}
	h, err := getHashFunction(hashFunction)
	if err != nil {
		return err
	}
	if err = rsa.VerifyPSS(rsaPublicKey, h, hashed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}); err != nil {
		return fmt.Errorf("verify signature: %s", err)
	}
	return nil
}

func rsaParsePartialResults(partialResults [][]byte) ([]partialrsa.RSAPartialResult, error) {
	rsaPartialResults := make([]partialrsa.RSAPartialResult, len(partialResults))
	for i := 0; i < len(partialResults); i++ {
		partialResult := partialResults[i]
		if err := rsaPartialResults[i].Decode(partialResult); err != nil {
			return nil, fmt.Errorf("unable to decode partial result at index %d: %w", i, err)
		}
	}
	return rsaPartialResults, nil
}
