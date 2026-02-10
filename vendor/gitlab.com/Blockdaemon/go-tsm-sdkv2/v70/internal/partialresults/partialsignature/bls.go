package partialsignature

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/blsvariant"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/bls"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/polynomial"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/secretshare"
)

const blsPartialSignatureVersion = 1

type BLSPartialSignature struct {
	Version     int
	Sharing     secretshare.SharingType
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	PublicKey   ec.Point
	SShare      ec.Point
	BLSVariant  string
}

func (e *BLSPartialSignature) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial signature: %s", err))
	}
	return buf.Bytes()
}

func (e *BLSPartialSignature) Decode(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewBLSPartialSignature(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare, publicKey ec.Point, blsVariant string) BLSPartialSignature {
	switch blsVariant {
	case blsvariant.BLS12381MinimalSignatureSize, blsvariant.BLS12381MinimalPubKeySize:
	default:
		panic(fmt.Sprintf("unsupported BLS variant: %s", blsVariant))
	}

	return BLSPartialSignature{
		Version:     blsPartialSignatureVersion,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		SShare:      sShare,
		BLSVariant:  blsVariant,
	}
}

func FinalizeBLSSignature(partialSignatures []BLSPartialSignature, message []byte) ([]byte, error) {
	var combiner blsPartialSignatureCombiner
	for _, partialSignature := range partialSignatures {
		err := combiner.Add(partialSignature)
		if err != nil {
			return nil, err
		}
	}
	return combiner.Signature(message)
}

type blsPartialSignatureCombiner struct {
	sharing        secretshare.SharingType
	threshold      int
	publicKey      ec.Point
	blsVariant     string
	si             map[int]ec.Point
	signatureCurve ec.Curve
}

func (e *blsPartialSignatureCombiner) Add(partialSignature BLSPartialSignature) error {
	if partialSignature.Version != blsPartialSignatureVersion {
		return fmt.Errorf("unsupported partial signature version: %d", partialSignature.Version)
	}

	signatureCurve, err := blsvariant.VariantToSignatureCurve(partialSignature.BLSVariant)
	if err != nil {
		return err
	}

	publicKeyCurve, err := blsvariant.VariantToPublicKeyCurve(partialSignature.BLSVariant)
	if err != nil {
		return err
	}

	switch partialSignature.ProtocolID {
	case "BLS":
	default:
		return fmt.Errorf("unsupported protocol for BLS: %s", partialSignature.ProtocolID)
	}

	if len(e.si) == 0 {
		e.sharing = partialSignature.Sharing
		e.threshold = partialSignature.Threshold
		if err = validatePoint(partialSignature.PublicKey, "public key", publicKeyCurve); err != nil {
			return err
		}
		e.publicKey = partialSignature.PublicKey
		e.blsVariant = partialSignature.BLSVariant
		e.si = map[int]ec.Point{}
		e.signatureCurve = signatureCurve
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
		if e.blsVariant != partialSignature.BLSVariant {
			return fmt.Errorf("%w: bls variant mismatch", ErrIncompatiblePartialSignatures)
		}
	}

	if err = validatePoint(partialSignature.SShare, "signature share", signatureCurve); err != nil {
		return err
	}
	e.si[partialSignature.PlayerIndex] = partialSignature.SShare

	return nil
}

func (e *blsPartialSignatureCombiner) Signature(message []byte) ([]byte, error) {
	if len(e.si) < e.threshold+1 {
		return nil, fmt.Errorf("not enough partial signatures")
	}

	var s ec.Point
	switch e.sharing {
	case secretshare.ShamirSharing:
		s = polynomial.InterpolatePlayersInExponent(e.signatureCurve.Zn().Zero(), e.threshold, e.si)
	case secretshare.AdditiveSharing:
		if len(e.si) > e.threshold+1 {
			return nil, fmt.Errorf("too many partial signatures")
		}
		s = e.signatureCurve.O()
		for _, v := range e.si {
			s = s.Add(v)
		}
	default:
		return nil, fmt.Errorf("unsupported sharing type: %d", e.sharing)
	}

	signature := s.EncodeCompressed()

	if len(message) > 0 {
		if validSignature := bls.Verify(e.publicKey.EncodeCompressed(), message, signature); !validSignature {
			return nil, fmt.Errorf("invalid signature")
		}
	}

	return signature, nil
}
