package partialsignature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/bip340"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/ed448"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/minaschnorr"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/sr25519"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/zilliqaschnorr"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/polynomial"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/schnorrvariant"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/secretshare"
)

const (
	schnorrPartialSignatureVersionV1 = 1
	schnorrPartialSignatureVersionV2 = 2
)

type SchnorrPartialSignature struct {
	Version        int
	Sharing        secretshare.SharingType
	ProtocolID     string
	PlayerIndex    int
	Threshold      int
	PublicKey      ec.Point
	R              ec.Point
	SShare         ec.Scalar
	Challenge      []byte
	SchnorrVariant string
}

func (e *SchnorrPartialSignature) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial signature: %s", err))
	}
	return buf.Bytes()
}

func (e *SchnorrPartialSignature) Decode(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSchnorrPartialSignature(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare ec.Scalar, R, publicKey ec.Point, challenge []byte, schnorrVariant string) SchnorrPartialSignature {
	var partialSignatureVersion int
	switch schnorrVariant {
	case schnorrvariant.Ed25519, schnorrvariant.Ed448, schnorrvariant.BIP340:
		partialSignatureVersion = schnorrPartialSignatureVersionV1
	case schnorrvariant.MinaSchnorr, schnorrvariant.ZilliqaSchnorr, schnorrvariant.Sr25519:
		partialSignatureVersion = schnorrPartialSignatureVersionV2
	default:
		panic(fmt.Sprintf("unsupported schnorr variant: %s", schnorrVariant))
	}
	return SchnorrPartialSignature{
		Version:        partialSignatureVersion,
		Sharing:        sharingType,
		ProtocolID:     protocolID,
		PlayerIndex:    playerIndex,
		Threshold:      threshold,
		PublicKey:      publicKey,
		R:              R,
		SShare:         sShare,
		Challenge:      challenge,
		SchnorrVariant: schnorrVariant,
	}
}

func FinalizeSchnorrSignature(partialSignatures []SchnorrPartialSignature, message []byte) ([]byte, error) {
	var combiner schnorrPartialSignatureCombiner
	for _, partialSignature := range partialSignatures {
		err := combiner.Add(partialSignature)
		if err != nil {
			return nil, err
		}
	}
	return combiner.Signature(message)
}

type schnorrPartialSignatureCombiner struct {
	sharing        secretshare.SharingType
	threshold      int
	publicKey      ec.Point
	schnorrVariant string
	r              ec.Point
	si             map[int]ec.Scalar
	challenge      []byte
}

func (e *schnorrPartialSignatureCombiner) Add(partialSignature SchnorrPartialSignature) error {
	if partialSignature.Version != schnorrPartialSignatureVersionV1 && partialSignature.Version != schnorrPartialSignatureVersionV2 {
		return fmt.Errorf("unsupported partial signature version: %d", partialSignature.Version)
	}

	if partialSignature.Version == schnorrPartialSignatureVersionV1 {
		var err error
		partialSignature.SchnorrVariant, err = schnorrVariantFromCurve(partialSignature.PublicKey.Curve())
		if err != nil {
			return err
		}
	}

	curve, err := schnorrvariant.VariantToCurve(partialSignature.SchnorrVariant)
	if err != nil {
		return err
	}

	switch partialSignature.ProtocolID {
	case "SEPD19S", "SCHNORR":
	default:
		return fmt.Errorf("unsupported protocol for schnorr: %s", partialSignature.ProtocolID)
	}

	if len(e.si) == 0 {
		e.sharing = partialSignature.Sharing
		e.threshold = partialSignature.Threshold
		if err = validatePoint(partialSignature.PublicKey, "public key", curve); err != nil {
			return err
		}
		e.publicKey = partialSignature.PublicKey
		e.schnorrVariant = partialSignature.SchnorrVariant
		if err = validatePoint(partialSignature.R, "R", curve); err != nil {
			return err
		}
		e.r = partialSignature.R
		e.si = map[int]ec.Scalar{}
		e.challenge = partialSignature.Challenge

	} else {
		if e.sharing != partialSignature.Sharing {
			return fmt.Errorf("%w: sharing type mismatch", ErrIncompatiblePartialSignatures)
		}
		if e.threshold != partialSignature.Threshold {
			return fmt.Errorf("%w: threshold mismatch", ErrIncompatiblePartialSignatures)
		}
		if !e.publicKey.Equals(partialSignature.PublicKey) {
			return fmt.Errorf("%w: public key mismatch", ErrIncompatiblePartialSignatures)
		}
		if e.schnorrVariant != partialSignature.SchnorrVariant {
			return fmt.Errorf("%w: schnorr variant mismatch", ErrIncompatiblePartialSignatures)
		}
		if !e.r.Equals(partialSignature.R) {
			return fmt.Errorf("%w: r value mismatch", ErrIncompatiblePartialSignatures)
		}
		if !bytes.Equal(e.challenge, partialSignature.Challenge) {
			return fmt.Errorf("%w: challenge mismatch", ErrIncompatiblePartialSignatures)
		}
	}

	if !e.publicKey.Curve().Zn().Equals(partialSignature.SShare.Field()) {
		return fmt.Errorf("signature share is from the wrong field")
	}

	if e.schnorrVariant == schnorrvariant.ZilliqaSchnorr && len(e.challenge) != ec.Secp256k1.Zn().ByteLen() {
		return fmt.Errorf("challenge has invalid length: %d", len(e.challenge))
	}

	e.si[partialSignature.PlayerIndex] = partialSignature.SShare

	return nil
}

func (e *schnorrPartialSignatureCombiner) Signature(message []byte) ([]byte, error) {
	if len(e.si) < e.threshold+1 {
		return nil, fmt.Errorf("not enough partial signatures")
	}

	var s ec.Scalar
	switch e.sharing {
	case secretshare.ShamirSharing:
		s = polynomial.InterpolatePlayers(e.publicKey.Curve().Zn().Zero(), e.threshold, e.si)
	case secretshare.AdditiveSharing:
		if len(e.si) > e.threshold+1 {
			return nil, fmt.Errorf("too many partial signatures")
		}
		s = e.publicKey.Curve().Zn().Zero()
		for _, v := range e.si {
			s = s.Add(v)
		}
	default:
		return nil, fmt.Errorf("unsupported sharing type: %d", e.sharing)
	}

	var signature []byte
	switch e.schnorrVariant {
	case schnorrvariant.Ed25519:
		signature = make([]byte, 64)
		copy(signature[:], e.r.Encode())
		copy(signature[32:], s.Encode())
		ec.ReverseSlice(signature[32:])
	case schnorrvariant.Ed448:
		signature = make([]byte, 114)
		copy(signature[:], e.r.Encode())
		copy(signature[57:], s.Encode())
		ec.ReverseSlice(signature[57:113])
	case schnorrvariant.BIP340:
		signature = make([]byte, 64)
		bytesR := e.r.EncodeCompressed()
		copy(signature, bytesR[1:33])
		copy(signature[32:], s.Encode())
	case schnorrvariant.MinaSchnorr:
		tx, _, err := e.r.Coordinates()
		if err != nil {
			return nil, err
		}
		rx := ec.PallasMinaFp.NewScalarWithModularReduction(tx)
		signature = make([]byte, 64)
		copy(signature[:32], rx.Encode())
		ec.ReverseSlice(signature[:32])
		copy(signature[32:], s.Encode())
		ec.ReverseSlice(signature[32:])
	case schnorrvariant.ZilliqaSchnorr:
		signature = append(e.challenge, s.Encode()...)
	case schnorrvariant.Sr25519:
		signature = make([]byte, 64)
		copy(signature[:32], e.r.EncodeCompressed())
		copy(signature[32:], s.Encode())
		ec.ReverseSlice(signature[32:])
		signature[63] |= 128
	default:
		return nil, fmt.Errorf("unsupported schnorr variant: %s", e.schnorrVariant)
	}

	if len(message) > 0 {
		var validSignature bool
		switch e.schnorrVariant {
		case schnorrvariant.Ed25519:
			validSignature = ed25519.Verify(e.publicKey.Encode(), message, signature)
		case schnorrvariant.Ed448:
			validSignature = ed448.Verify(e.publicKey.Encode(), message, signature)
		case schnorrvariant.BIP340:
			bip340PublicKey := e.publicKey.EncodeCompressed()
			validSignature = bip340.Verify(bip340PublicKey[1:33], message, signature)
		case schnorrvariant.MinaSchnorr:
			var input minaschnorr.SignInput
			if err := input.Decode(message); err != nil {
				return nil, err
			}
			validSignature = minaschnorr.Verify(e.publicKey.EncodeCompressed(), &input, signature)
		case schnorrvariant.ZilliqaSchnorr:
			validSignature = zilliqaschnorr.Verify(e.publicKey.EncodeCompressed(), message, signature)
		case schnorrvariant.Sr25519:
			validSignature = sr25519.Verify(e.publicKey.EncodeCompressed(), []byte("substrate"), message, signature)
		default:
			return nil, fmt.Errorf("unsupported schnorr variant: %s", e.schnorrVariant)
		}
		if !validSignature {
			return nil, fmt.Errorf("invalid signature")
		}
	}

	return signature, nil
}

// This is only used for partial signature version 1
func schnorrVariantFromCurve(curve ec.Curve) (string, error) {
	switch curve.Name() {
	case ec.Edwards25519.Name():
		return schnorrvariant.Ed25519, nil
	case ec.Edwards448.Name():
		return schnorrvariant.Ed448, nil
	case ec.Secp256k1.Name():
		return schnorrvariant.BIP340, nil
	default:
		return "", fmt.Errorf("unsupported elliptic curve: %s", curve.Name())
	}
}
