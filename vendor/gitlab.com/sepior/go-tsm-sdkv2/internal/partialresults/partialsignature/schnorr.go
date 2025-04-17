package partialsignature

import (
	"bytes"
	"crypto/ed25519"
	"encoding/gob"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/bip340"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ed448"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/polynomial"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/secretshare"
)

const schnorrPartialSignatureVersion = 1

type SchnorrPartialSignature struct {
	Version     int
	Sharing     secretshare.SharingType
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	PublicKey   ec.Point
	R           ec.Point
	SShare      ec.Scalar
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

func NewSchnorrPartialSignature(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare ec.Scalar, R, publicKey ec.Point) SchnorrPartialSignature {
	return SchnorrPartialSignature{
		Version:     schnorrPartialSignatureVersion,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		R:           R,
		SShare:      sShare,
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
	sharing    secretshare.SharingType
	protocolID string
	threshold  int
	publicKey  ec.Point
	r          ec.Point
	si         map[int]ec.Scalar
}

func (e *schnorrPartialSignatureCombiner) Add(partialSignature SchnorrPartialSignature) error {
	if partialSignature.Version < 1 || partialSignature.Version > schnorrPartialSignatureVersion {
		return fmt.Errorf("unsupported partial signature version: %d", partialSignature.Version)
	}

	if len(e.si) == 0 {
		e.sharing = partialSignature.Sharing
		e.protocolID = partialSignature.ProtocolID
		e.threshold = partialSignature.Threshold
		if !partialSignature.PublicKey.IsInLargeSubgroup() {
			return fmt.Errorf("public key is not in the large prime order subgroup")
		}
		e.publicKey = partialSignature.PublicKey
		if !partialSignature.PublicKey.IsInLargeSubgroup() {
			return fmt.Errorf("r value is not in the large prime order subgroup")
		}
		e.r = partialSignature.R
		e.si = map[int]ec.Scalar{}
	} else {
		if e.sharing != partialSignature.Sharing {
			return fmt.Errorf("sharing type mismatch")
		}
		if e.protocolID != partialSignature.ProtocolID {
			return fmt.Errorf("protocol mismatch")
		}
		if e.threshold != partialSignature.Threshold {
			return fmt.Errorf("threshold mismatch")
		}
		if !e.publicKey.Equals(partialSignature.PublicKey) {
			return fmt.Errorf("public key mismatch")
		}
		if !e.r.Equals(partialSignature.R) {
			return fmt.Errorf("r value mismatch")
		}
	}

	if !e.publicKey.Curve().Zn().Equals(partialSignature.SShare.Field()) {
		return fmt.Errorf("signature share is from the wrong field")
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
	switch e.publicKey.Curve().Name() {
	case ec.Edwards25519.Name():
		signature = make([]byte, 64)
		copy(signature[:], e.r.Encode())
		copy(signature[32:], s.Encode())
		ec.ReverseSlice(signature[32:])
	case ec.Edwards448.Name():
		signature = make([]byte, 114)
		copy(signature[:], e.r.Encode())
		copy(signature[57:], s.Encode())
		ec.ReverseSlice(signature[57:113])
	case ec.Secp256k1.Name():
		signature = make([]byte, 64)
		bytesR := e.r.EncodeCompressed()
		copy(signature, bytesR[1:33])
		copy(signature[32:], s.Encode())
	default:
		return nil, fmt.Errorf("no schnorr signature for elliptic curve: %s", e.publicKey.Curve().Name())
	}

	if len(message) > 0 {
		var validSignature bool
		switch e.publicKey.Curve().Name() {
		case ec.Edwards25519.Name():
			validSignature = ed25519.Verify(e.publicKey.Encode(), message, signature)
		case ec.Edwards448.Name():
			validSignature = ed448.Verify(e.publicKey.Encode(), message, signature)
		case ec.Secp256k1.Name():
			bip340PublicKey := e.publicKey.EncodeCompressed()
			validSignature = bip340.Verify(bip340PublicKey[1:33], message, signature)
		default:
			return nil, fmt.Errorf("no schnorr signature for elliptic curve: %s", e.publicKey.Curve().Name())
		}
		if !validSignature {
			return nil, fmt.Errorf("invalid signature")
		}
	}

	return signature, nil
}
