package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Version 1: Initial
const hmacPartialResultVersionSimple = 1

type HMACPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// Fields used for partial result type: Simple, version 1
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
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleHMACPartialResult(protocolID string, threshold, playerIndex int, digestShare []byte) HMACPartialResult {
	return HMACPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           hmacPartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		DigestShare:       digestShare,
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
	partialResultType PartialResultType
	version           int
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple, version 1
	digests map[int][]byte
}

func (e *hmacPartialResultCombiner) Add(partialResult HMACPartialResult) error {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.digests = make(map[int][]byte)
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
		if e.version != hmacPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", hmacPartialResultVersionSimple, e.version)
		}
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
