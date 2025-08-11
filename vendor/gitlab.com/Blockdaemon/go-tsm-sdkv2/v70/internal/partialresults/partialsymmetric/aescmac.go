package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
)

// Version 1: Initial
const aesCMACPartialResultVersionSimple = 1

// Version 1: Initial
// Version 2: Changed mac key structure
const aesCMACPartialResultVersionMAC2 = 2

type AESCMACPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// Fields used for partial result type: Simple, version 1
	// All shares hold the output in the clear.
	DigestShare []byte

	// Fields for partial result type: MAC2, version 2
	// Player 1 (Bob)'s share consists of the output (digest) and an information theoretical mac tag
	// on the output, and where Player 0 (Alice)'s share consist of an information theoretical mac key for the output.
	DigestBytes       []byte
	DigestMacTagBytes []byte
	DigestMacKeyBytes []byte
}

func (e *AESCMACPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESCMACPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > aesCMACPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesCMACPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCMACPartialResult(protocolID string, threshold, playerIndex int, digestShare []byte) AESCMACPartialResult {
	return AESCMACPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesCMACPartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		DigestShare:       digestShare,
	}
}

func FinalizeAESCMAC(partialResults ...AESCMACPartialResult) (digest []byte, err error) {
	var combiner aesCMACPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.Digest()
}

type aesCMACPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	digests map[int][]byte

	// For partial result type: MAC2, version 2
	digest       bits.BitSet
	digestMacTag bits.BitSet
	digestMacKey bits.BitSet
}

func (e *aesCMACPartialResultCombiner) Add(partialResult AESCMACPartialResult) (err error) {
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
		for _, v := range e.digests {
			if !bytes.Equal(v, partialResult.DigestShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.digests[partialResult.PlayerIndex] = partialResult.DigestShare

	case MAC2:
		const alice, bob = 0, 1
		switch partialResult.PlayerIndex {
		case alice:
			e.digestMacKey, err = bits.Deserialize(partialResult.DigestMacKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.digest, err = bits.Deserialize(partialResult.DigestBytes)
			if err != nil {
				return err
			}

			e.digestMacTag, err = bits.Deserialize(partialResult.DigestMacTagBytes)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("mac2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %q", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *aesCMACPartialResultCombiner) Digest() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesCMACPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesCMACPartialResultVersionSimple, e.version)
		}

		if len(e.digests) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.digests {
			return v, nil
		}

	case MAC2:
		if e.version != aesCMACPartialResultVersionMAC2 {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesCMACPartialResultVersionMAC2, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		if err := checkInfoMac(e.digest, e.digestMacTag, e.digestMacKey); err != nil {
			return nil, err
		}

		return e.digest.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCMACPartialResultMAC2Alice(protocolID string, digestMacKey bits.BitSet) AESCMACPartialResult {
	return AESCMACPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesCMACPartialResultVersionMAC2,
		PlayerIndex:       0, // Alice
		Threshold:         1,
		DigestMacKeyBytes: digestMacKey.Serialize(),
	}
}

func NewAESCMACPartialResultMAC2Bob(protocolID string, digest, digestMacTag bits.BitSet) AESCMACPartialResult {
	return AESCMACPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesCMACPartialResultVersionMAC2,
		PlayerIndex:       1, // Bob
		Threshold:         1,
		DigestBytes:       digest.Serialize(),
		DigestMacTagBytes: digestMacTag.Serialize(),
	}
}
