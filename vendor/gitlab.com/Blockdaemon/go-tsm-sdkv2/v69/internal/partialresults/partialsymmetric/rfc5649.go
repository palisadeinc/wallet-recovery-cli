package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const rfc5649WrapPartialResultVersion = 1

type RFC5649WrapPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// Fields used for partial result type: Simple
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != rfc5649WrapPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", rfc5649WrapPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleRFC5649WrapPartialResult(protocolID string, threshold, playerIndex int, encryptedBlobShare []byte) RFC5649WrapPartialResult {
	return RFC5649WrapPartialResult{
		Version:           rfc5649WrapPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		PlayerIndex:       playerIndex,
		Threshold:         threshold,

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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	encryptedBlobs map[int][]byte
}

func (e *rfc5649WrapPartialResultCombiner) Add(partialResult RFC5649WrapPartialResult) error {
	if partialResult.Version < 1 || partialResult.Version > rfc5649WrapPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.encryptedBlobs = make(map[int][]byte)
	}

	if e.protocolID != partialResult.ProtocolID {
		return fmt.Errorf("protocol mismatch (expected %s, got %s)", e.protocolID, partialResult.ProtocolID)
	}

	if e.partialResultType != partialResult.PartialResultType {
		return fmt.Errorf("partial result type mismatch (expected %s, got %s)", e.partialResultType.String(), partialResult.PartialResultType.String())
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
