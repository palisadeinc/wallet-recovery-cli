package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Version 1: Initial
const rfc5649WrapPartialResultVersionSimple = 1

type RFC5649WrapPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// Fields used for partial result type: Simple, version 1
	// All shares hold the output in the clear.
	EncryptedBlobShare []byte
}

func (e *RFC5649WrapPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *RFC5649WrapPartialResult) Decode(b []byte) error {
	var v struct {
		ProtocolID        string
		PartialResultType PartialResultType
		Version           int
	}
	if err := gob.NewDecoder(bytes.NewBuffer(b)).Decode(&v); err != nil {
		return err
	}

	switch v.PartialResultType {
	case Simple:
		if v.Version < 1 || v.Version > aesGCMEncryptPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesGCMEncryptPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleRFC5649WrapPartialResult(protocolID string, threshold, playerIndex int, encryptedBlobShare []byte) RFC5649WrapPartialResult {
	return RFC5649WrapPartialResult{
		ProtocolID:         protocolID,
		PartialResultType:  Simple,
		Version:            rfc5649WrapPartialResultVersionSimple,
		PlayerIndex:        playerIndex,
		Threshold:          threshold,
		EncryptedBlobShare: encryptedBlobShare,
	}
}

func FinalizeRFC5649Wrap(partialResults ...RFC5649WrapPartialResult) (encryptedBlob []byte, err error) {
	var combiner rfc5649WrapPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.EncryptedBlob()
}

type rfc5649WrapPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple, version 1
	encryptedBlobs map[int][]byte
}

func (e *rfc5649WrapPartialResultCombiner) Add(partialResult RFC5649WrapPartialResult) error {
	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.version = partialResult.Version
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold
		e.encryptedBlobs = make(map[int][]byte)
	}

	if partialResult.ProtocolID != "SYM" {
		return fmt.Errorf("unsupported protocol for SYM: %s", partialResult.ProtocolID)
	}

	if e.partialResultType != partialResult.PartialResultType {
		return fmt.Errorf("partial result type mismatch (expected %s, got %s)", e.partialResultType.String(), partialResult.PartialResultType.String())
	}

	if e.version != partialResult.Version {
		return fmt.Errorf("partial result version mismatch (expected %d, got %d)", e.version, partialResult.Version)
	}

	if e.threshold != partialResult.Threshold {
		return fmt.Errorf("threshold mismatch (expected %d, got %d)", e.threshold, partialResult.Threshold)
	}

	switch e.partialResultType {
	case Simple:
		for _, d := range e.encryptedBlobs {
			if !bytes.Equal(d, partialResult.EncryptedBlobShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.encryptedBlobs[partialResult.PlayerIndex] = partialResult.EncryptedBlobShare

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *rfc5649WrapPartialResultCombiner) EncryptedBlob() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != rfc5649WrapPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", rfc5649WrapPartialResultVersionSimple, e.version)
		}

		if len(e.encryptedBlobs) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}

		for _, d := range e.encryptedBlobs {
			return d, nil
		}

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}
