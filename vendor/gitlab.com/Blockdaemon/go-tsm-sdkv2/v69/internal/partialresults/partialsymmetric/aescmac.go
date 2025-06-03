package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bch"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bits"
)

const aesCMACPartialResultVersion = 1

type AESCMACPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// Fields used for partial result type: Simple
	// All shares hold the output in the clear.
	DigestShare []byte

	// These fields are for BCH2 partial results, where Player 1 (Bob)'s share consists of the output (digest) and a bch mac tag
	// on the output, and where Player 0 (Alice)'s share consist of a bch mac key for the output.
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

func NewSimpleAESCMACPartialResult(protocolID string, threshold, playerIndex int, digestShare []byte) AESCMACPartialResult {
	return AESCMACPartialResult{
		Version:           aesCMACPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		DigestShare: digestShare,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	digests map[int][]byte

	// For partial result type: BCH2
	digest       bits.BitSet
	digestMacTag bits.BitSet
	digestMacKey bits.BitSet
}

func (e *aesCMACPartialResultCombiner) Add(partialResult AESCMACPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesCMACPartialResultVersion {
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
		for _, v := range e.digests {
			if !bytes.Equal(v, partialResult.DigestShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.digests[partialResult.PlayerIndex] = partialResult.DigestShare

	case BCH2:
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
			return fmt.Errorf("xorbch2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %q", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *aesCMACPartialResultCombiner) Digest() ([]byte, error) {
	switch e.partialResultType {

	case Simple:

		if len(e.digests) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.digests {
			return v, nil
		}

	case BCH2:

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		code, err := bch.NewCode(128, 40)
		if err != nil {
			panic(err)
		}

		if err = checkExtendedBCH(code, e.digest, e.digestMacTag, e.digestMacKey); err != nil {
			return nil, err
		}

		return e.digest.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCMACPartialResultBCH2Alice(digestMacKey bits.BitSet) AESCMACPartialResult {
	return AESCMACPartialResult{
		Version:           aesCMACPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		DigestMacKeyBytes: digestMacKey.Serialize(),
	}
}

func NewAESCMACPartialResultBCH2Bob(digest, digestMacTag bits.BitSet) AESCMACPartialResult {
	return AESCMACPartialResult{
		Version:           aesCMACPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		DigestBytes:       digest.Serialize(),
		DigestMacTagBytes: digestMacTag.Serialize(),
	}
}
