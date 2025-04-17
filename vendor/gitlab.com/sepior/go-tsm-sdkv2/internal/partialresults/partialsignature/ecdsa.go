package partialsignature

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ecdsa"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/polynomial"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/secretshare"
)

const ecdsaPartialSignatureVersion = 1

type ECDSAPartialSignature struct {
	Version     int
	Sharing     secretshare.SharingType
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	PublicKey   ec.Point
	R           ec.Point
	SShare      ec.Scalar
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

func NewECDSAPartialSignature(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare ec.Scalar, R, publicKey ec.Point) ECDSAPartialSignature {
	return ECDSAPartialSignature{
		Version:     ecdsaPartialSignatureVersion,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		R:           R,
		SShare:      sShare,
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
	sharing    secretshare.SharingType
	protocolID string
	threshold  int
	publicKey  ec.Point
	r          ec.Point
	si         map[int]ec.Scalar
}

func (e *ecdsaPartialSignatureCombiner) Add(partialSignature ECDSAPartialSignature) error {
	if partialSignature.Version < 1 || partialSignature.Version > ecdsaPartialSignatureVersion {
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
		if !partialSignature.R.IsInLargeSubgroup() {
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

func (e *ecdsaPartialSignatureCombiner) Signature(messageHash []byte) (ecdsa.Signature, error) {
	if len(e.si) < e.threshold+1 {
		return ecdsa.Signature{}, fmt.Errorf("not enough partial signatures")
	}

	var s ec.Scalar
	switch e.sharing {
	case secretshare.ShamirSharing:
		s = polynomial.InterpolatePlayers(e.publicKey.Curve().Zn().Zero(), e.threshold, e.si)
	case secretshare.AdditiveSharing:
		if len(e.si) > e.threshold+1 {
			return ecdsa.Signature{}, fmt.Errorf("too many partial signatures")
		}
		s = e.publicKey.Curve().Zn().Zero()
		for _, v := range e.si {
			s = s.Add(v)
		}
	default:
		return ecdsa.Signature{}, fmt.Errorf("unsupported sharing type: %d", e.sharing)
	}

	signature := ecdsa.NewSignature(e.r, s)

	if len(messageHash) > 0 {
		if !ecdsa.VerifyASN1(e.publicKey, messageHash, signature.ASN1()) {
			return ecdsa.Signature{}, fmt.Errorf("invalid signature")
		}
	}

	return signature, nil
}
