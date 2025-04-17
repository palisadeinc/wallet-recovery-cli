package tsm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/caching"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/bip340"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ed448"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/derivekeys"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/ers"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/partialresults/partialsignature"
)

// SchnorrFinalizeSignature will construct a Schnorr signature by combining data from a list of partial signatures. If
// the message is specified then the resulting signature is verified before returning.
func SchnorrFinalizeSignature(message []byte, partialSignatures [][]byte) (signature []byte, err error) {
	schnorrPartialSignatures := make([]partialsignature.SchnorrPartialSignature, len(partialSignatures))
	for i := 0; i < len(partialSignatures); i++ {
		partialSignature := partialSignatures[i]
		err = schnorrPartialSignatures[i].Decode(partialSignature)
		if err != nil {
			// Legacy partial signatures from SDKv1 are wrapped in an array in a struct
			var legacySchnorrPartialSignatures = struct {
				PartialSignatures []partialsignature.SchnorrPartialSignature
			}{}

			dec := gob.NewDecoder(bytes.NewBuffer(partialSignature))
			err = dec.Decode(&legacySchnorrPartialSignatures)
			if err != nil || len(legacySchnorrPartialSignatures.PartialSignatures) != 1 {
				return nil, fmt.Errorf("finalize signature: unable to decode partial signature, index: %d, value: %s, error: %w", i, hex.EncodeToString(partialSignature), err)
			}
			schnorrPartialSignatures[i] = legacySchnorrPartialSignatures.PartialSignatures[0]
		}
	}
	return partialsignature.FinalizeSchnorrSignature(schnorrPartialSignatures, message)
}

// SchnorrVerifySignature verifies the Schnorr signature and returns an error if it is not valid.
func SchnorrVerifySignature(pkixPublicKey, message, signature []byte) error {
	publicKey, err := schnorrPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("verify signature: unable to convert public key to point: %s", err)
	}

	switch publicKey.Curve().Name() {
	case ec.Edwards448.Name():
		if !ed448.Verify(publicKey.EncodeCompressed(), message, signature) {
			return fmt.Errorf("verify signature: verification failed")
		}
	case ec.Edwards25519.Name():
		if !ed25519.Verify(publicKey.EncodeCompressed(), message, signature) {
			return fmt.Errorf("verify signature: verification failed")
		}
	case ec.Secp256k1.Name():
		if !bip340.Verify(publicKey.EncodeCompressed()[1:], message, signature) {
			return fmt.Errorf("verify signature: verification failed")
		}
	}
	return nil
}

// SchnorrDerivePublicKey derives a public key from the given public key, chain code and path.
func SchnorrDerivePublicKey(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivedPublicKey []byte, err error) {
	derivedKey, err := schnorrDerive(pkixPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	derivedPublicKey, err = schnorrPointToPKIXPublicKey(derivedKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return derivedPublicKey, nil
}

// SchnorrDeriveChainCode derives a chain code from the given public key, chain code and path.
func SchnorrDeriveChainCode(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivedChainCode []byte, err error) {
	derivedKey, err := schnorrDerive(pkixPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive chain code: %w", err)
	}
	return derivedKey.ChainCode, nil
}

// SchnorrFinalizeRecoveryData combines a number of partial recovery data into a single recovery data and validates that
// the resulting recovery data can actually be used to recover the private key in the future. Only someone in possession
// of the RSA private key corresponding to ersPublic key and who knows the ersLabel can recover the private key.
func SchnorrFinalizeRecoveryData(partialRecoveryData [][]byte, ersPublicKey *rsa.PublicKey, ersLabel []byte) (recoveryData []byte, err error) {
	schnorrPartialRecoveryData := make([]ers.PartialRecoveryData, len(partialRecoveryData))
	for i := 0; i < len(partialRecoveryData); i++ {
		err = unmarshalJSON(bytes.NewReader(partialRecoveryData[i]), &schnorrPartialRecoveryData[i])
		if err != nil {
			return nil, fmt.Errorf("finalize recovery data: unable to decode partial recovery data %d: %w", i, err)
		}
	}
	jsonRecoveryData, err := ers.RecoveryDataFinalize(schnorrPartialRecoveryData, ersPublicKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("finalize recovery data: unable to generate recovery data: %w", err)
	}

	out, err := json.Marshal(jsonRecoveryData)
	if err != nil {
		return nil, err
	}

	return out, nil
}

// SchnorrValidateRecoveryData validates that anyone in possession of the RSA private key corresponding to ersPublic
// key and who knows the ersLabel can recover the private key from the given recovery data.
func SchnorrValidateRecoveryData(recoveryData []byte, pkixPublicKey []byte, ersPublicKey *rsa.PublicKey, ersLabel []byte) (err error) {
	var jsonRecoveryData ers.RecoveryData
	err = unmarshalJSON(bytes.NewReader(recoveryData), &jsonRecoveryData)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to decode recovery data: %w", err)
	}

	publicKey, err := schnorrPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to convert public key to point: %s", err)
	}

	err = ers.Validate(jsonRecoveryData, ersPublicKey, ersLabel, publicKey)
	if err != nil {
		return fmt.Errorf("validate recovery data: validation failed: %s", err)
	}

	return nil
}

// SchnorrRecoverPrivateKey recovers the private key and master chain code from the given recovery data, assuming that the
// ersPrivateKey corresponds to the ersPublicKey used to generate the recovery data. The ersLabel must also be the same
// value used to generate the recovery data. This ensures that the one doing the recovery cannot claim to be unaware of
// the label, and hence the label can be used e.g. for storing a recovery policy.
func SchnorrRecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, ersLabel []byte) (recoveredPrivateKey *SchnorrRecoveredPrivateKey, err error) {
	var jsonRecoveryData ers.RecoveryData
	err = unmarshalJSON(bytes.NewReader(recoveryData), &jsonRecoveryData)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode recovery data: %w", err)
	}

	auxDataPublic := ers.RecoverAuxDataPublic(jsonRecoveryData)
	var recoveredAuxDataPublic ers.SchnorrAuxDataPublic
	err = json.Unmarshal(auxDataPublic, &recoveredAuxDataPublic)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode public auxiliary data: %w", err)
	}
	if !isValidSchnorrAlgorithm(recoveredAuxDataPublic.Algorithm) {
		return nil, fmt.Errorf("recover private key: recovery data is not for for a Schnorr private key")
	}

	privateKey, err := ers.RecoverPrivateKey(jsonRecoveryData, ersPrivateKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to recover private key: %w", err)
	}

	auxDataPrivate, err := ers.RecoverAuxDataPrivate(jsonRecoveryData, ersPrivateKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to recover private auxiliary data: %w", err)
	}
	var recoveredAuxDataPrivate ers.SchnorrAuxDataPrivate
	err = json.Unmarshal(auxDataPrivate, &recoveredAuxDataPrivate)
	if err != nil {
		return nil, fmt.Errorf("recover private key: unable to decode private auxiliary data: %w", err)
	}

	return &SchnorrRecoveredPrivateKey{
		PrivateKey:      privateKey.Encode(),
		MasterChainCode: recoveredAuxDataPrivate.MasterChainCode,
	}, nil
}

func schnorrDerive(pkixPublicKey []byte, chainCode []byte, derivationPath []uint32) (derivekeys.DerivedPublicKey, error) {
	publicKey, err := schnorrPKIXPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return derivekeys.DerivedPublicKey{}, fmt.Errorf("unable to decode public key: %s", err)
	}
	derivedInfo, err := derivekeys.DeriveSchnorrPublicKey(publicKey, chainCode, derivationPath, caching.NoCache())
	if err != nil {
		return derivekeys.DerivedPublicKey{}, fmt.Errorf("derivation error: %s", err)
	}
	return derivedInfo, nil
}

func schnorrPKIXPublicKeyToPoint(pkixPublicKey []byte) (ec.Point, error) {
	p, err := pkixPublicKeyToPoint(pkixPublicKey)
	if err != nil {
		return ec.Point{}, err
	}
	if !p.Curve().SupportsSchnorr() {
		return ec.Point{}, fmt.Errorf("not a schnorr public key")
	}
	return p, nil
}

func schnorrPointToPKIXPublicKey(p ec.Point) ([]byte, error) {
	if !p.Curve().SupportsSchnorr() {
		return nil, fmt.Errorf("elliptic curve cannot be used for schnorr: %s", p.Curve().Name())
	}
	return pointToPKIXPublicKey(p)
}

func isValidSchnorrAlgorithm(algorithm string) bool {
	switch algorithm {
	case "EdDSA": // Legacy
		return true
	case "Ed25519", "Ed448", "BIP-340":
		return true
	default:
		return false
	}
}
