package tsm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/crypto/bip340"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/crypto/ed448"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/derivekeys"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ers"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/partialresults/partialsignature"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
)

const (
	SchnorrAlgorithmEd25519 = "Ed25519"
	SchnorrAlgorithmEd448   = "Ed448"
	SchnorrAlgorithmBIP340  = "BIP-340"
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

// SchnorrSign generates a Schnorr signature from a raw private key and a message. This method is intended for use after
// recovering a raw private key with SchnorrRecoverPrivateKey or deriving one using SchnorrDerivePrivateKey.
func SchnorrSign(schnorrAlgorithm string, rawPrivateKey []byte, message []byte) (signature []byte, err error) {
	var curve ec.Curve
	switch schnorrAlgorithm {
	case SchnorrAlgorithmEd25519:
		curve = ec.Edwards25519
	case SchnorrAlgorithmEd448:
		curve = ec.Edwards448
	case SchnorrAlgorithmBIP340:
		curve = ec.Secp256k1
	default:
		return nil, fmt.Errorf("unsupported schnorr algorithm: %s", schnorrAlgorithm)
	}

	privateKey, err := curve.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode private key: %s", err)
	}
	publicKey := curve.G().Multiply(privateKey)

	if schnorrAlgorithm == SchnorrAlgorithmEd25519 {
		r := ec.Edwards25519.Zn().NewRandomScalar()
		R := ec.Edwards25519.G().Multiply(r)
		sigHash := sha512.New()
		_, _ = sigHash.Write(R.Encode())
		_, _ = sigHash.Write(publicKey.Encode())
		_, _ = sigHash.Write(message)
		mHash := sigHash.Sum(nil)
		ec.ReverseSlice(mHash)
		h := publicKey.Curve().Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(mHash))
		s := r.Add(h.Multiply(privateKey))

		signature = make([]byte, 64)
		copy(signature[:], R.Encode())
		copy(signature[32:], s.Encode())
		ec.ReverseSlice(signature[32:])

		return signature, nil
	} else if schnorrAlgorithm == SchnorrAlgorithmEd448 {
		r := ec.Edwards448.Zn().NewRandomScalar()
		R := ec.Edwards448.G().Multiply(r)
		dom4 := fmt.Sprintf("%s%s%s%s", "SigEd448", string(byte(0)), string(byte(len(""))), "")
		sigHash := sha3.NewShake256()
		_, _ = sigHash.Write([]byte(dom4))
		_, _ = sigHash.Write(R.Encode())
		_, _ = sigHash.Write(publicKey.Encode())
		_, _ = sigHash.Write(message)
		var mHash [114]byte
		_, _ = io.ReadFull(sigHash, mHash[:])
		ec.ReverseSlice(mHash[:])
		h := publicKey.Curve().Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(mHash[:]))
		s := r.Add(h.Multiply(privateKey))

		signature = make([]byte, 114)
		copy(signature[:], R.Encode())
		copy(signature[57:], s.Encode())
		ec.ReverseSlice(signature[57:113])

		return signature, nil
	} else {
		r := ec.Secp256k1.Zn().NewRandomScalar()
		R := ec.Secp256k1.G().Multiply(r)
		xR, yR, err := R.Coordinates()
		if err != nil {
			return nil, fmt.Errorf("failed to get coordinates of R: %s", err)
		}
		if yR.Bit(0) == 1 {
			r = r.Negate()
		}
		bytesR := make([]byte, 32)
		xR.FillBytes(bytesR)
		e := bip340Hash("BIP0340/challenge", bytesR, publicKey.EncodeCompressed()[1:], message)
		ePrime, err := ec.Secp256k1.Zn().DecodeScalar(e)
		if err != nil {
			return nil, fmt.Errorf("bad challenge value: %s", err)
		}
		s := r.Add(ePrime.Multiply(privateKey))

		signature = make([]byte, 64)
		bytesR = R.EncodeCompressed()
		copy(signature, bytesR[1:33])
		copy(signature[32:], s.Encode())

		return signature, nil
	}
}

func bip340Hash(name string, values ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	tagHash := h.Sum(nil)

	h.Reset()
	h.Write(tagHash)
	h.Write(tagHash)
	for _, v := range values {
		h.Write(v)
	}

	return h.Sum(nil)
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

// SchnorrDerivePrivateKey derives a private key for a given Schnorr algorithm, the given private key in raw big endian format, chain code and path.
func SchnorrDerivePrivateKey(schnorrAlgorithm string, rawPrivateKey, chainCode []byte, derivationPath []uint32) (derivedPrivateKey []byte, err error) {
	derivedKey, err := schnorrDerivePrivateKey(schnorrAlgorithm, rawPrivateKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive private key: %s", err)
	}
	return derivedKey.Encode(), nil
}

// SchnorrDerivePublicKey derives a public key from the given public key, chain code and path.
func SchnorrDerivePublicKey(pkixPublicKey, chainCode []byte, derivationPath []uint32) (derivedPublicKey []byte, err error) {
	derivedKey, err := schnorrDerivePublicKey(pkixPublicKey, chainCode, derivationPath)
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
	derivedKey, err := schnorrDerivePublicKey(pkixPublicKey, chainCode, derivationPath)
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

func schnorrDerivePrivateKey(schnorrAlgorithm string, rawPrivateKey, chainCode []byte, derivationPath []uint32) (ec.Scalar, error) {
	var zn ec.Field
	switch schnorrAlgorithm {
	case SchnorrAlgorithmEd25519:
		zn = ec.Edwards25519.Zn()
	case SchnorrAlgorithmEd448:
		zn = ec.Edwards448.Zn()
	case SchnorrAlgorithmBIP340:
		zn = ec.Secp256k1.Zn()
	default:
		return ec.Scalar{}, fmt.Errorf("unsupported schnorr algorithm: %s", schnorrAlgorithm)
	}

	privateKey, err := zn.DecodeScalar(rawPrivateKey)
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("unable to decode private key: %s", err)
	}
	derivedPrivateKey, err := derivekeys.DeriveSchnorrPrivateKey(privateKey, chainCode, derivationPath, caching.NoCache())
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("derivation error: %s", err)
	}
	return derivedPrivateKey, nil
}

func schnorrDerivePublicKey(pkixPublicKey []byte, chainCode []byte, derivationPath []uint32) (derivekeys.DerivedPublicKey, error) {
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
