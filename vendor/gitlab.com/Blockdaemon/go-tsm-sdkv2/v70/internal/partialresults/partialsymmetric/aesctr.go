package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
)

// Version 1: Initial
const aesCTRPartialResultVersionSimple = 1

// Version 1: Initial
// Version 2: Changed mac key structure
const aesCTRPartialResultVersionMAC2 = 2

type AESCTRPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// These fields are for result type Simple, version 1
	// All shares hold the output in the clear.
	KeyStreamShare []byte

	// These fields are for partial result type MAC2, version 2
	// Bob's share consists of key stream and key stream mac tag and Alice's share contains key stream mac key.
	KeyStreamBytes       []byte
	KeyStreamMacTagBytes []byte
	KeyStreamMacKeyBytes []byte
}

func (e *AESCTRPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESCTRPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > aesCTRPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesCTRPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCTRPartialResult(protocolID string, threshold, playerIndex int, keyStreamShare []byte) AESCTRPartialResult {
	return AESCTRPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesCTRPartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		KeyStreamShare:    keyStreamShare,
	}
}

func FinalizeAESCTR(partialResults ...AESCTRPartialResult) (keyStream []byte, err error) {
	var combiner aesCTRPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.CTRStream()
}

type aesCTRPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	ctrStreams map[int][]byte

	// For partial result type: MAC2, version 2
	keyStream       bits.BitSet
	keyStreamMacTag bits.BitSet
	keyStreamMacKey bits.BitSet
}

func (e *aesCTRPartialResultCombiner) Add(partialResult AESCTRPartialResult) (err error) {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.ctrStreams = make(map[int][]byte)
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
		for _, v := range e.ctrStreams {
			if !bytes.Equal(v, partialResult.KeyStreamShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.ctrStreams[partialResult.PlayerIndex] = partialResult.KeyStreamShare

	case MAC2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:
			e.keyStreamMacKey, err = bits.Deserialize(partialResult.KeyStreamMacKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.keyStream, err = bits.Deserialize(partialResult.KeyStreamBytes)
			if err != nil {
				return err
			}

			e.keyStreamMacTag, err = bits.Deserialize(partialResult.KeyStreamMacTagBytes)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("mac2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *aesCTRPartialResultCombiner) CTRStream() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesCTRPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesCTRPartialResultVersionSimple, e.version)
		}

		if len(e.ctrStreams) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.ctrStreams {
			return v, nil
		}

	case MAC2:
		if e.version != aesCTRPartialResultVersionMAC2 {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesCTRPartialResultVersionMAC2, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		if err := checkInfoMac(e.keyStream, e.keyStreamMacTag, e.keyStreamMacKey); err != nil {
			return nil, err
		}

		return e.keyStream.Bytes(), nil

	default:
		panic(fmt.Sprint("unknown protocol: ", e.partialResultType.String()))
	}

	panic("unreachable")
}

func NewAESCTRPartialResultMAC2Alice(protocolID string, keyStreamMacKey bits.BitSet) AESCTRPartialResult {
	return AESCTRPartialResult{
		ProtocolID:           protocolID,
		PartialResultType:    MAC2,
		Version:              aesCTRPartialResultVersionMAC2,
		PlayerIndex:          0, // Alice
		Threshold:            1,
		KeyStreamMacKeyBytes: keyStreamMacKey.Serialize(),
	}
}

func NewAESCTRPartialResultMAC2Bob(protocolID string, keyStream, keyStreamMacTag bits.BitSet) AESCTRPartialResult {
	return AESCTRPartialResult{
		ProtocolID:           protocolID,
		Version:              aesCTRPartialResultVersionMAC2,
		PartialResultType:    MAC2,
		PlayerIndex:          1, // Bob
		Threshold:            1,
		KeyStreamBytes:       keyStream.Serialize(),
		KeyStreamMacTagBytes: keyStreamMacTag.Serialize(),
	}
}
