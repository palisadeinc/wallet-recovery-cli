package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

// Version 1: Initial
const an10922PartialResultVersionSimple = 1

type AN10922ChecksumPartialResult struct {
	ProtocolID        string
	Version           int
	PartialResultType PartialResultType

	PlayerIndex int
	Threshold   int

	// Fields used for partial result type: Simple, version 1
	// All shares hold the output in the clear.
	ChecksumShare []byte
}

func (e *AN10922ChecksumPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AN10922ChecksumPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > an10922PartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAN10922ChecksumPartialResult(protocolID string, threshold, playerIndex int, checksumShare []byte) AN10922ChecksumPartialResult {
	return AN10922ChecksumPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           an10922PartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		ChecksumShare:     checksumShare,
	}
}

func FinalizeAN10922Checksum(partialResults ...AN10922ChecksumPartialResult) (checksum []byte, err error) {
	var combiner an10922ChecksumPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.Checksum()
}

type an10922ChecksumPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	checksums map[int][]byte
}

func (e *an10922ChecksumPartialResultCombiner) Add(partialResult AN10922ChecksumPartialResult) error {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.checksums = make(map[int][]byte)
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
		for _, v := range e.checksums {
			if !bytes.Equal(v, partialResult.ChecksumShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.checksums[partialResult.PlayerIndex] = partialResult.ChecksumShare

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *an10922ChecksumPartialResultCombiner) Checksum() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != an10922PartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", an10922PartialResultVersionSimple, e.version)
		}
		if len(e.checksums) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.checksums {
			return v, nil
		}
	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}
