package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
)

const anAN10922PartialResultVersion = 1

type AN10922ChecksumPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// Fields used for partial result type: Simple
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesCMACPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesCMACPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAN10922ChecksumPartialResult(protocolID string, threshold, playerIndex int, checksumShare []byte) AN10922ChecksumPartialResult {
	return AN10922ChecksumPartialResult{
		Version:           aesCMACPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		ChecksumShare: checksumShare,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	checksums map[int][]byte
}

func (e *an10922ChecksumPartialResultCombiner) Add(partialResult AN10922ChecksumPartialResult) error {
	if partialResult.Version < 1 || partialResult.Version > anAN10922PartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.checksums = make(map[int][]byte)
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
