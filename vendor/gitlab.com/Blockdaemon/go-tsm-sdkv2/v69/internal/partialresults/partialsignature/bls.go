package partialsignature

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/crypto/bls"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/polynomial"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/secretshare"
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

func NewBLSPartialSignature(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, sShare, publicKey ec.Point) BLSPartialSignature {
	return BLSPartialSignature{
		Version:     blsPartialSignatureVersion,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		PublicKey:   publicKey,
		SShare:      sShare,
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
	sharing    secretshare.SharingType
	protocolID string
	threshold  int
	publicKey  ec.Point
	si         map[int]ec.Point
	sigCurve   ec.Curve
}

func (e *blsPartialSignatureCombiner) Add(partialSignature BLSPartialSignature) error {
	if partialSignature.Version < 1 || partialSignature.Version > blsPartialSignatureVersion {
		return fmt.Errorf("unsupported partial signature version: %d", partialSignature.Version)
	}

	if len(e.si) == 0 {
		e.sharing = partialSignature.Sharing
		e.protocolID = partialSignature.ProtocolID
		e.threshold = partialSignature.Threshold
		if pairingCurve, err := partialSignature.PublicKey.Curve().PairingCurve(); err != nil {
			return fmt.Errorf("public key elliptic curve does not support pairings")
		} else {
			if partialSignature.PublicKey.Curve().Equals(pairingCurve.E1()) {
				e.sigCurve = pairingCurve.E2()
			} else {
				e.sigCurve = pairingCurve.E1()
			}
		}
		if !partialSignature.PublicKey.IsInLargeSubgroup() {
			return fmt.Errorf("public key is not in the large prime order subgroup")
		}
		e.publicKey = partialSignature.PublicKey
		e.si = map[int]ec.Point{}
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
	}

	if !e.sigCurve.Equals(partialSignature.SShare.Curve()) {
		return fmt.Errorf("signature share is from the wrong elliptic curve")
	}
	if !partialSignature.SShare.IsInLargeSubgroup() {
		return fmt.Errorf("signature share is not in the large prime order subgroup")
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
		s = polynomial.InterpolatePlayersInExponent(e.sigCurve.Zn().Zero(), e.threshold, e.si)
	case secretshare.AdditiveSharing:
		if len(e.si) > e.threshold+1 {
			return nil, fmt.Errorf("too many partial signatures")
		}
		s = e.sigCurve.O()
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
