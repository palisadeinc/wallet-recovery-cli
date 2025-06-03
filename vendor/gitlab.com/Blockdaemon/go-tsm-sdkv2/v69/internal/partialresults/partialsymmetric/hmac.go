package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const hmacPartialResultVersion = 1

type HMACPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// Fields used for partial result type: Simple
	// All shares hold the output in the clear.
	DigestShare []byte
}

func (e *HMACPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *HMACPartialResult) Decode(b []byte) error {
	var v struct {
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != hmacPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", hmacPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleHMACPartialResult(protocolID string, threshold, playerIndex int, digestShare []byte) HMACPartialResult {
	return HMACPartialResult{
		Version:           hmacPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		DigestShare: digestShare,
	}
}

func FinalizeHMAC(partialResults ...HMACPartialResult) (digest []byte, err error) {
	var combiner hmacPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.Digest()
}

type hmacPartialResultCombiner struct {
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	digests map[int][]byte
}

func (e *hmacPartialResultCombiner) Add(partialResult HMACPartialResult) error {
	if partialResult.Version < 1 || partialResult.Version > hmacPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.digests = make(map[int][]byte)
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

	// Ensure we get at most one share from each player
	if _, exists := e.playerIDs[partialResult.PlayerIndex]; exists {
		return fmt.Errorf("already got share from player: %d", partialResult.PlayerIndex)
	}
	e.playerIDs[partialResult.PlayerIndex] = 1

	switch e.partialResultType {
	case Simple:

		for _, d := range e.digests {
			if !bytes.Equal(d, partialResult.DigestShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.digests[partialResult.PlayerIndex] = partialResult.DigestShare

	default:
		return fmt.Errorf("unsupported partial result type: %q", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *hmacPartialResultCombiner) Digest() ([]byte, error) {
	switch e.partialResultType {

	case Simple:

		if len(e.digests) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}

		for _, d := range e.digests {
			return d, nil
		}
	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}
