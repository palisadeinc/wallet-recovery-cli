package partialsignature

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/ecdsa"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/polynomial"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/secretshare"
)

const (
	ecdsaPartialSignatureVersionV1 = 1
	ecdsaPartialSignatureVersionV2 = 2
)

var ErrIncompatiblePartialSignatures = errors.New("incompatible partial signatures")

type ECDSAPartialSignature struct {
	Version     int
	Sharing     secretshare.SharingType
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	PublicKey   ec.Point
	R           ec.Point
	SShare      ec.Scalar // V1
	U, W        ec.Scalar // V2
}

func (e *ECDSAPartialSignature) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial signature: %s", err))
	}
	return buf.Bytes()
}

func (e *ECDSAPartialSignature) Decode(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewECDSAPartialSignatureV1(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare ec.Scalar, R, publicKey ec.Point) ECDSAPartialSignature {
	return ECDSAPartialSignature{
		Version:     ecdsaPartialSignatureVersionV1,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		R:           R,
		SShare:      sShare,
	}
}

func NewECDSAPartialSignatureV2(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, u, w ec.Scalar, R, publicKey ec.Point) ECDSAPartialSignature {
	return ECDSAPartialSignature{
		Version:     ecdsaPartialSignatureVersionV2,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		R:           R,
		U:           u,
		W:           w,
	}
}

func FinalizeECDSASignature(partialSignatures []ECDSAPartialSignature, messageHash []byte) (ecdsa.Signature, error) {
	var combiner ecdsaPartialSignatureCombiner
	for _, partialSignature := range partialSignatures {
		err := combiner.Add(partialSignature)
		if err != nil {
			return ecdsa.Signature{}, err
		}
	}
	return combiner.Signature(messageHash)
}

type ecdsaPartialSignatureCombiner struct {
	version   int
	sharing   secretshare.SharingType
	threshold int
	publicKey ec.Point
	r         ec.Point
	ui        map[int]ec.Scalar
	wi        map[int]ec.Scalar
}

func (e *ecdsaPartialSignatureCombiner) Add(partialSignature ECDSAPartialSignature) error {
	if partialSignature.Version != ecdsaPartialSignatureVersionV1 && partialSignature.Version != ecdsaPartialSignatureVersionV2 {
		return fmt.Errorf("unsupported partial signature version: %d", partialSignature.Version)
	}

	switch partialSignature.ProtocolID {
	case "SEPH18S", "DKLS19", "ECDSA":
	default:
		return fmt.Errorf("unsupported protocol for ECDSA: %s", partialSignature.ProtocolID)
	}

	if len(e.ui) == 0 {
		e.version = partialSignature.Version
		e.sharing = partialSignature.Sharing
		e.threshold = partialSignature.Threshold
		if err := validatePoint(partialSignature.PublicKey, "public key", nil); err != nil {
			return err
		}
		e.publicKey = partialSignature.PublicKey
		if err := validatePoint(partialSignature.R, "R", nil); err != nil {
			return err
		}
		e.r = partialSignature.R
		e.ui = map[int]ec.Scalar{}
		e.wi = map[int]ec.Scalar{}
	} else {
		if e.version != partialSignature.Version {
			return fmt.Errorf("%w: version mismatch", ErrIncompatiblePartialSignatures)
		}
		if e.sharing != partialSignature.Sharing {
			return fmt.Errorf("%w: sharing type mismatch", ErrIncompatiblePartialSignatures)
		}
		if e.threshold != partialSignature.Threshold {
			return fmt.Errorf("%w: threshold mismatch", ErrIncompatiblePartialSignatures)
		}
		if !e.publicKey.Equals(partialSignature.PublicKey) {
			return fmt.Errorf("%w: public key mismatch", ErrIncompatiblePartialSignatures)
		}
		if !e.r.Equals(partialSignature.R) {
			return fmt.Errorf("%w: r value mismatch", ErrIncompatiblePartialSignatures)
		}
	}

	var u ec.Scalar
	if partialSignature.Version == ecdsaPartialSignatureVersionV1 {
		u = partialSignature.SShare
	} else {
		u = partialSignature.U
	}
	if !e.publicKey.Curve().Zn().Equals(u.Field()) {
		return fmt.Errorf("u share is from the wrong field")
	}
	e.ui[partialSignature.PlayerIndex] = u

	if partialSignature.Version == ecdsaPartialSignatureVersionV2 {
		if !e.publicKey.Curve().Zn().Equals(partialSignature.W.Field()) {
			return fmt.Errorf("w share is from the wrong field")
		}
		e.wi[partialSignature.PlayerIndex] = partialSignature.W
	}

	return nil
}

func (e *ecdsaPartialSignatureCombiner) Signature(messageHash []byte) (ecdsa.Signature, error) {
	if len(e.ui) < e.threshold+1 {
		return ecdsa.Signature{}, fmt.Errorf("not enough partial signatures")
	}

	isV2 := e.version == ecdsaPartialSignatureVersionV2
	if isV2 && len(e.ui) != len(e.wi) {
		return ecdsa.Signature{}, fmt.Errorf("mismatch between number of u and w values")
	}

	var u, w ec.Scalar
	switch e.sharing {
	case secretshare.ShamirSharing:
		u = polynomial.InterpolatePlayers(e.publicKey.Curve().Zn().Zero(), e.threshold, e.ui)
		if isV2 {
			w = polynomial.InterpolatePlayers(e.publicKey.Curve().Zn().Zero(), e.threshold, e.wi)
		}
	case secretshare.AdditiveSharing:
		if len(e.ui) > e.threshold+1 {
			return ecdsa.Signature{}, fmt.Errorf("too many partial signatures")
		}
		u = e.publicKey.Curve().Zn().Zero()
		for _, v := range e.ui {
			u = u.Add(v)
		}
		if isV2 {
			w = e.publicKey.Curve().Zn().Zero()
			for _, v := range e.wi {
				w = w.Add(v)
			}
		}
	default:
		return ecdsa.Signature{}, fmt.Errorf("unsupported sharing type: %d", e.sharing)
	}

	var s ec.Scalar
	if isV2 {
		if u.Equals(u.Field().Zero()) {
			return ecdsa.Signature{}, fmt.Errorf("u is zero")
		}
		s = w.Divide(u)
	} else {
		s = u
	}
	signature := ecdsa.NewSignature(e.r, s)

	if len(messageHash) > 0 {
		if !ecdsa.VerifyASN1(e.publicKey, messageHash, signature.ASN1()) {
			return ecdsa.Signature{}, fmt.Errorf("invalid signature")
		}
	}

	return signature, nil
}

func validatePoint(p ec.Point, pDescription string, expectedCurve ec.Curve) error {
	if expectedCurve != nil {
		if !expectedCurve.Equals(p.Curve()) {
			return fmt.Errorf("%s is from the wrong elliptic curve", pDescription)
		}
	} else {
		expectedCurve = p.Curve()
	}
	if p.Equals(expectedCurve.O()) {
		return fmt.Errorf("%s is point at infinity", pDescription)
	}
	if !p.IsInLargeSubgroup() {
		return fmt.Errorf("%s is not in the large prime order subgroup", pDescription)
	}
	return nil
}
