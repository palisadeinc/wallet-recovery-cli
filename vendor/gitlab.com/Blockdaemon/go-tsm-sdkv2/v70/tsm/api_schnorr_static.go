package tsm

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/bip340"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/ed448"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/minaschnorr"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/sr25519"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/zilliqaschnorr"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/derivekeys"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ers"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/partialresults/partialsignature"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/schnorrvariant"
	"math/big"
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
func SchnorrSign(schnorrVariant string, rawPrivateKey []byte, message []byte) (signature []byte, err error) {
	curve, err := schnorrvariant.VariantToCurve(schnorrVariant)
	if err != nil {
		return nil, fmt.Errorf("unsupported schnorr variant: %s", schnorrVariant)
	}
	privateKey, err := curve.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode private key: %s", err)
	}
	publicKey := curve.G().Multiply(privateKey)

	switch schnorrVariant {
	case SchnorrEd25519:
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
	case SchnorrEd448:
		return ed448.SignRaw(rawPrivateKey, publicKey.EncodeCompressed(), message), nil
	case SchnorrBIP340:
		publicKeyX, _, err := publicKey.Coordinates()
		if err != nil {
			return nil, fmt.Errorf("failed to get coordinates of public key: %s", err)
		}
		rawPublicKey := make([]byte, bip340.PublicKeySize)
		publicKeyX.FillBytes(rawPublicKey)
		return bip340.SignRaw(rawPrivateKey, rawPublicKey, message), nil
	case SchnorrMina:
		var signInput minaschnorr.SignInput
		if err = signInput.Decode(message); err != nil {
			return nil, fmt.Errorf("failed to decode message: %s", err)
		}
		return minaschnorr.SignRaw(rawPrivateKey, &signInput), nil
	case SchnorrZilliqa:
		return zilliqaschnorr.SignRaw(rawPrivateKey, message), nil
	case SchnorrSr25519:
		return sr25519.SignRaw(rawPrivateKey, publicKey.EncodeCompressed(), []byte("substrate"), message), nil
	default:
		return nil, fmt.Errorf("unsupported schnorr variant: %s", schnorrVariant)
	}
}

// SchnorrVerifySignature verifies the Schnorr signature and returns an error if it is not valid.
func SchnorrVerifySignature(jsonPublicKey, message, signature []byte) error {
	publicKey, err := decodeECPublicKey(jsonPublicKey)
	if err != nil {
		return fmt.Errorf("verify signature: unable to decode public key: %w", err)
	}
	if !publicKey.isSchnorr() {
		return fmt.Errorf("verify signature: not a schnorr public key")
	}
	variantPublicKey := publicKey.value.EncodeCompressed()

	var isValid bool
	switch publicKey.Scheme {
	case SchnorrEd25519:
		isValid = ed25519.Verify(variantPublicKey, message, signature)
	case SchnorrEd448:
		isValid = ed448.Verify(variantPublicKey, message, signature)
	case SchnorrBIP340:
		isValid = bip340.Verify(variantPublicKey[1:], message, signature)
	case SchnorrMina:
		var signInput minaschnorr.SignInput
		err = signInput.Decode(message)
		if err != nil {
			return fmt.Errorf("verify signature: unable to decode message: %s", err)
		}
		isValid = minaschnorr.Verify(variantPublicKey, &signInput, signature)
	case SchnorrZilliqa:
		isValid = zilliqaschnorr.Verify(variantPublicKey, message, signature)
	case SchnorrSr25519:
		isValid = sr25519.Verify(variantPublicKey, []byte("substrate"), message, signature)
	default:
		return fmt.Errorf("unsupported schnorr variant: %s", publicKey.Scheme)
	}
	if !isValid {
		return fmt.Errorf("verify signature: verification failed")
	}
	return nil
}

// SchnorrMinaPrepareMessage prepares a message for signing with MinaSchnorr, by wrapping it in a Mina specific format.
func SchnorrMinaPrepareMessage(message []byte) []byte {
	return minaschnorr.PrepareMessage(message).Encode()
}

// SchnorrMinaPrepareRawInput prepares data in a Mina specific format for signing. Data to be signed consists
// of a number of Fp elements (where Fp is the finite field from the PallasMina curve) represented as 32 byte
// big-endian numbers, followed by a bitvector represented as a little endian byte array.
func SchnorrMinaPrepareRawInput(networkID int, fieldElements [][]byte, bitVector []byte, bitVectorLength int) ([]byte, error) {
	fpElements := make([]ec.Scalar, len(fieldElements))
	for i := 0; i < len(fieldElements); i++ {
		var err error
		fpElements[i], err = ec.PallasMinaFp.DecodeScalar(fieldElements[i])
		if err != nil {
			return nil, fmt.Errorf("invalid field element at index %d: %s", i, err)
		}
	}

	vector := bits.NewFromBytes(bitVector).Subset(0, bitVectorLength)
	return minaschnorr.PrepareRawInput(minaschnorr.NetworkType(networkID), fpElements, vector).Encode(), nil
}

// SchnorrMinaPreparePaymentTransaction prepares a payment transaction for signing with MinaSchnorr, by wrapping it in a
// Mina specific format. If you need to sign different types of data, consider using the SchnorrMinaPrepareRawInput function.
func SchnorrMinaPreparePaymentTransaction(networkID int, fromAddr, toAddr string, fee, amount uint64, nonce, validUntil uint32, memo string) ([]byte, error) {
	signInput, err := minaschnorr.PrepareTransaction(minaschnorr.NetworkType(networkID), minaschnorr.PaymentTransaction, fromAddr, toAddr, fee, amount, nonce, validUntil, memo)
	if err != nil {
		return nil, err
	}
	return signInput.Encode(), nil
}

// SchnorrMinaPrepareDelegationTransaction prepares a delegation transaction for signing with MinaSchnorr, by wrapping it in a
// Mina specific format. If you need to sign different types of data, consider using the SchnorrMinaPrepareRawInput function.
func SchnorrMinaPrepareDelegationTransaction(networkID int, fromAddr, toAddr string, fee uint64, nonce, validUntil uint32, memo string) ([]byte, error) {
	signInput, err := minaschnorr.PrepareTransaction(minaschnorr.NetworkType(networkID), minaschnorr.DelegationTransaction, fromAddr, toAddr, fee, 0, nonce, validUntil, memo)
	if err != nil {
		return nil, err
	}
	return signInput.Encode(), nil
}

// SchnorrDerivePrivateKey derives a private key for a given Schnorr variant, the given private key in raw big endian format, chain code and path.
func SchnorrDerivePrivateKey(schnorrVariant string, rawPrivateKey, chainCode []byte, derivationPath []uint32) (derivedPrivateKey []byte, err error) {
	derivedKey, err := schnorrDerivePrivateKey(schnorrVariant, rawPrivateKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive private key: %s", err)
	}
	return derivedKey.Encode(), nil
}

// SchnorrDerivePublicKey derives a public key from the given public key, chain code and path.
func SchnorrDerivePublicKey(jsonPublicKey, chainCode []byte, derivationPath []uint32) (derivedPublicKey []byte, err error) {
	schnorrVariant, publicKey, _, err := schnorrDerivePublicKey(jsonPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	derivedECPublicKey, err := newECPublicKey(schnorrVariant, "", publicKey.Encode())
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	return derivedECPublicKey.Encode(), nil
}

// SchnorrDeriveChainCode derives a chain code from the given public key, chain code and path.
func SchnorrDeriveChainCode(jsonPublicKey, chainCode []byte, derivationPath []uint32) (derivedChainCode []byte, err error) {
	_, _, derivedChainCode, err = schnorrDerivePublicKey(jsonPublicKey, chainCode, derivationPath)
	if err != nil {
		return nil, fmt.Errorf("derive chain code: %w", err)
	}
	return derivedChainCode, nil
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
func SchnorrValidateRecoveryData(recoveryData []byte, jsonPublicKey []byte, ersPublicKey *rsa.PublicKey, ersLabel []byte) (err error) {
	var jsonRecoveryData ers.RecoveryData
	err = unmarshalJSON(bytes.NewReader(recoveryData), &jsonRecoveryData)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to decode recovery data: %w", err)
	}

	publicKey, err := decodeECPublicKey(jsonPublicKey)
	if err != nil {
		return fmt.Errorf("validate recovery data: unable to decode public key: %w", err)
	}
	if !publicKey.isSchnorr() {
		return fmt.Errorf("validate recovery data: not a schnorr public key")
	}

	err = ers.Validate(jsonRecoveryData, ersPublicKey, ersLabel, publicKey.value)
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

	if recoveredAuxDataPublic.Algorithm != "EdDSA" {
		if _, err := schnorrvariant.VariantToCurve(recoveredAuxDataPublic.Algorithm); err != nil {
			return nil, fmt.Errorf("recover private key: recovery data is not for for a Schnorr private key")
		}
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

	if recoveredAuxDataPublic.Algorithm == "EdDSA" {
		switch len(recoveredAuxDataPrivate.MasterChainCode) {
		case ec.Edwards25519.Zn().ByteLen():
			recoveredAuxDataPublic.Algorithm = "Ed25519"
		case ec.Edwards448.Zn().ByteLen():
			recoveredAuxDataPublic.Algorithm = "Ed448"
		}
	}

	return &SchnorrRecoveredPrivateKey{
		PrivateKey:      privateKey.Encode(),
		MasterChainCode: recoveredAuxDataPrivate.MasterChainCode,
		SchnorrVariant:  recoveredAuxDataPublic.Algorithm,
	}, nil
}

func schnorrDerivePrivateKey(schnorrVariant string, rawPrivateKey, chainCode []byte, derivationPath []uint32) (ec.Scalar, error) {
	curve, err := schnorrvariant.VariantToCurve(schnorrVariant)
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("unsupported schnorr variant: %s", schnorrVariant)
	}

	privateKey, err := curve.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("unable to decode private key: %s", err)
	}
	publicKey := curve.G().Multiply(privateKey)

	derivedPrivateKey, err := derivekeys.DeriveSchnorrPrivateKey(schnorrVariant, privateKey, publicKey, chainCode, derivationPath, caching.NoCache())
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("derivation error: %s", err)
	}
	return derivedPrivateKey, nil
}

func schnorrDerivePublicKey(jsonPublicKey []byte, chainCode []byte, derivationPath []uint32) (string, ec.Point, []byte, error) {
	publicKey, err := decodeECPublicKey(jsonPublicKey)
	if err != nil {
		return "", ec.Point{}, nil, fmt.Errorf("unable to decode public key: %s", err)
	}
	if !publicKey.isSchnorr() {
		return "", ec.Point{}, nil, fmt.Errorf("not a schnorr public key")
	}
	derivedInfo, err := derivekeys.DeriveSchnorrPublicKey(publicKey.Scheme, publicKey.value, chainCode, derivationPath, caching.NoCache())
	if err != nil {
		return "", ec.Point{}, nil, fmt.Errorf("derivation error: %s", err)
	}
	return publicKey.Scheme, derivedInfo.PublicKey, derivedInfo.ChainCode, nil
}
