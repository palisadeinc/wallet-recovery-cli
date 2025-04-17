package tsm

import (
	"bytes"
	"crypto/rsa"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/caching"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ecdsa"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/derivekeys"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/ers"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/partialresults/partialsignature"
)

// ECDSASignature represents an ECDSA signature.
type ECDSASignature struct {
	curve     ec.Curve
	signature ecdsa.Signature
}

// RecoveryID returns the recovery ID which can be used to recover the public key given the signature and the message.
//
// The least significant bit of the recoveryID is 1 if and only if the sign of the s scalar was switched in order to
// return the smallest value of s. The remaining bits of the recoveryID contains z such that R = (r+zN,y) where N is
// the modulus. Note that for secp256k1 z is zero except with negligible probability, but this may not be the case for
// other curves.
func (e *ECDSASignature) RecoveryID() int {
	return e.signature.RecoveryID()
}

// ASN1 returns the signature as a DER encoded ASN.1 signature.
func (e *ECDSASignature) ASN1() []byte {
	return e.signature.ASN1()
}

// R returns the r value of the signature in big endian format.
func (e *ECDSASignature) R() []byte {
	r := make([]byte, e.curve.Zn().ByteLen())
	e.signature.R().FillBytes(r)
	return r
}

// S returns the s value of the signature in big endian format.
//
// For ECDSA, it holds that if (r,s) is a valid signature, then (r,-s) is also a
// valid signature. The signature returned here always contains the smallest of the two possible valid values of s,
// meaning that 0 < s < N / 2 + 1, where N is the modulus.
func (e *ECDSASignature) S() []byte {
	s := make([]byte, e.curve.Zn().ByteLen())
	e.signature.S().FillBytes(s)
	return s
}

// ECDSAFinalizeSignature will construct an ASN.1 DER encoding of a signature by combining data from a list of partial
// signatures. The result also contains the recoveryID which can be used to get the public key from the signature. If
// the message hash is specified then the resulting signature is verified before returning.
func ECDSAFinalizeSignature(messageHash []byte, partialSignatures [][]byte) (signature *ECDSASignature, err error) {
	ecdsaPartialSignatures := make([]partialsignature.ECDSAPartialSignature, len(partialSignatures))
	for i := 0; i < len(partialSignatures); i++ {
		partialSignature := partialSignatures[i]
		err = ecdsaPartialSignatures[i].Decode(partialSignature)
		if err != nil {
			// Legacy partial signatures from SDKv1 are wrapped in an array in a struct
			var legacyECDSAPartialSignatures = struct {
				PartialSignatures []partialsignature.ECDSAPartialSignature
			}{}

			dec := gob.NewDecoder(bytes.NewBuffer(partialSignature))
			err = dec.Decode(&legacyECDSAPartialSignatures)
			if err != nil || len(legacyECDSAPartialSignatures.PartialSignatures) != 1 {
				return nil, fmt.Errorf("finalize signature: unable to decode partial signature, index: %d, value: %s, error: %w", i, hex.EncodeToString(partialSignature), err)
			}
			ecdsaPartialSignatures[i] = legacyECDSAPartialSignatures.PartialSignatures[0]
		}
	}
	sig, err := partialsignature.FinalizeECDSASignature(ecdsaPartialSignatures, messageHash)
	if err != nil {
		return nil, err
	}

	curve := ecdsaPartialSignatures[0].PublicKey.Curve()
	r := make([]byte, curve.Zn().ByteLen())
	sig.R().FillBytes(r)
	s := make([]byte, curve.Zn().ByteLen())
	sig.S().FillBytes(s)

	return &ECDSASignature{
		curve:     curve,
		signature: sig,
	}, nil
}

// ECDSAVerifySignature verifies the ECDSA signature and returns an error if it is not valid.
//
// The pkixPublicKey is the ASN.1 DER encoded SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1).
func ECDSAVerifySignature(pkixPublicKey, messageHash, asn1Signature []byte) error {
	publicKey, err := ecdsaPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("verify signature: unable to convert public key to point: %s", err)
	}

	if !ecdsa.VerifyASN1(publicKey, messageHash, asn1Signature) {
		return fmt.Errorf("verify signature: verification failed")
	}

	return nil
}

// ECDSADerivePublicKey derives a public key from the given public key, chain code and BIP-32 path. The result is a
// SubjectPublicKeyInfo structure (see RFC 5280, Section 4.1). Note that only the elliptic curve secp256k1 supports
// BIP-32 key derivation.
func ECDSADerivePublicKey(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivedPublicKey []byte, err error) {
	derivedKey, err := ecdsaDerive(pkixPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	derivedPublicKey, err = ecdsaPointToPKIXPublicKey(derivedKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return derivedPublicKey, nil
}

// ECDSADeriveChainCode derives a chain code from the given public key, chain code and BIP-32 path. Note that only the
// elliptic curve secp256k1 supports BIP-32 key derivation.
func ECDSADeriveChainCode(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivedChainCode []byte, err error) {
	derivedKey, err := ecdsaDerive(pkixPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive chain code: %w", err)
	}
	return derivedKey.ChainCode, nil
}

// ECDSAFinalizeRecoveryData combines a number of partial recovery data into a single recovery data and validates that
// the resulting recovery data can actually be used to recover the private key in the future. Only someone in possession
// of the RSA private key corresponding to ersPublic key and who knows the ersLabel can recover the private key.
func ECDSAFinalizeRecoveryData(partialRecoveryData [][]byte, ersPublicKey *rsa.PublicKey, ersLabel []byte) (recoveryData []byte, err error) {
	ecdsaPartialRecoveryData := make([]ers.PartialRecoveryData, len(partialRecoveryData))
	for i := 0; i < len(partialRecoveryData); i++ {
		err = unmarshalJSON(bytes.NewReader(partialRecoveryData[i]), &ecdsaPartialRecoveryData[i])
		if err != nil {
			return nil, fmt.Errorf("finalize recovery data: unable to decode partial recovery data %d: %w", i, err)
		}
	}
	jsonRecoveryData, err := ers.RecoveryDataFinalize(ecdsaPartialRecoveryData, ersPublicKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("finalize recovery data: unable to generate recovery data: %w", err)
	}

	out, err := json.Marshal(jsonRecoveryData)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// ECDSAValidateRecoveryData validates that anyone in possession of the RSA private key corresponding to ersPublic
// key and who knows the ersLabel can recover the private key from the given recovery data.
func ECDSAValidateRecoveryData(recoveryData []byte, pkixPublicKey []byte, ersPublicKey *rsa.PublicKey, ersLabel []byte) (err error) {
	var jsonRecoveryData ers.RecoveryData
	err = unmarshalJSON(bytes.NewReader(recoveryData), &jsonRecoveryData)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to decode recovery data: %w", err)
	}

	publicKey, err := ecdsaPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to convert public key to point: %s", err)
	}

	err = ers.Validate(jsonRecoveryData, ersPublicKey, ersLabel, publicKey)
	if err != nil {
		return fmt.Errorf("validate recovery data: validation failed: %s", err)
	}

	return nil
}

// ECDSARecoverPrivateKey recovers the private key and master chain code from the given recovery data, assuming that the
// ersPrivateKey corresponds to the ersPublicKey used to generate the recovery data. The ersLabel must also be the same
// value used to generate the recovery data. This ensures that the one doing the recovery cannot claim to be unaware of
// the label, and hence the label can be used e.g. for storing a recovery policy.
func ECDSARecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, ersLabel []byte) (recoveredPrivateKey *ECDSARecoveredPrivateKey, err error) {
	var jsonRecoveryData ers.RecoveryData
	err = unmarshalJSON(bytes.NewReader(recoveryData), &jsonRecoveryData)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode recovery data: %w", err)
	}

	auxDataPublic := ers.RecoverAuxDataPublic(jsonRecoveryData)
	var recoveredAuxDataPublic ers.ECDSAAuxDataPublic
	err = json.Unmarshal(auxDataPublic, &recoveredAuxDataPublic)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode public auxiliary data: %w", err)
	}
	if recoveredAuxDataPublic.Algorithm != "ECDSA" {
		return nil, fmt.Errorf("recover private key: recovery data is not for for an ECDSA private key")
	}

	privateKey, err := ers.RecoverPrivateKey(jsonRecoveryData, ersPrivateKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to recover private key: %w", err)
	}

	auxDataPrivate, err := ers.RecoverAuxDataPrivate(jsonRecoveryData, ersPrivateKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to recover private auxiliary data: %w", err)
	}
	var recoveredAuxDataPrivate ers.ECDSAAuxDataPrivate
	err = json.Unmarshal(auxDataPrivate, &recoveredAuxDataPrivate)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode private auxiliary data: %w", err)
	}

	return &ECDSARecoveredPrivateKey{
		PrivateKey:      privateKey.Encode(),
		MasterChainCode: recoveredAuxDataPrivate.MasterChainCode,
	}, nil
}

func ecdsaDerive(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivekeys.DerivedPublicKey, error) {
	publicKey, err := ecdsaPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return derivekeys.DerivedPublicKey{}, fmt.Errorf("unable to decode public key: %s", err)
	}
	derivedInfo, err := derivekeys.DeriveECDSAPublicKey(publicKey, chainCode, derivationPath, caching.NoCache())
	if err != nil {
		return derivekeys.DerivedPublicKey{}, fmt.Errorf("derivation error: %s", err)
	}
	return derivedInfo, nil
}

func ecdsaPKIXPublicKeyToPoint(pkixPublicKey []byte) (ec.Point, error) {
	p, err := pkixPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return ec.Point{}, err
	}
	if !p.Curve().SupportsECDSA() {
		return ec.Point{}, fmt.Errorf("not an ECDSA public key")
	}
	return p, nil
}

func ecdsaPointToPKIXPublicKey(p ec.Point) ([]byte, error) {
	if !p.Curve().SupportsECDSA() {
		return nil, fmt.Errorf("elliptic curve cannot be used for ECDSA: %s", p.Curve().Name())
	}
	return pointToPKIXPublicKey(p)
}
