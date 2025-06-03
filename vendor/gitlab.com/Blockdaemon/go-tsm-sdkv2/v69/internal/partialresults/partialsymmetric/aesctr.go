package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bch"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bits"
)

const aesCTRPartialResultVersion = 1

type AESCTRPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// These fields are for Simple partial results where all shares hold the output in the clear.
	KeyStreamShare []byte

	// These fields are for BCH2 partial results, where Bob's share consists of key stream and key stream mac tag
	// and Alice's share contains key stream mac key.
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesCTRPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesCTRPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCTRPartialResult(protocolID string, threshold, playerIndex int, keyStreamShare []byte) AESCTRPartialResult {
	return AESCTRPartialResult{
		Version:           aesCTRPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		KeyStreamShare: keyStreamShare,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	ctrStreams map[int][]byte

	// For partial result type: BCH2
	keyStream       bits.BitSet
	keyStreamMacTag bits.BitSet
	keyStreamMacKey bits.BitSet
}

func (e *aesCTRPartialResultCombiner) Add(partialResult AESCTRPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesCTRPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.ctrStreams = make(map[int][]byte)
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
		for _, v := range e.ctrStreams {
			if !bytes.Equal(v, partialResult.KeyStreamShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.ctrStreams[partialResult.PlayerIndex] = partialResult.KeyStreamShare

	case BCH2:
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
			return fmt.Errorf("xorbch2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *aesCTRPartialResultCombiner) CTRStream() ([]byte, error) {
	switch e.partialResultType {

	case Simple:
		if len(e.ctrStreams) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.ctrStreams {
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

		if err = checkExtendedBCH(code, e.keyStream, e.keyStreamMacTag, e.keyStreamMacKey); err != nil {
			return nil, err
		}

		return e.keyStream.Bytes(), nil

	default:
		panic(fmt.Sprint("unknown protocol: ", e.partialResultType.String()))
	}

	panic("unreachable")
}

func NewAESCTRPartialResultBCH2Alice(keyStreamMacKey bits.BitSet) AESCTRPartialResult {
	return AESCTRPartialResult{
		Version:           aesCTRPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		KeyStreamMacKeyBytes: keyStreamMacKey.Serialize(),
	}
}

func NewAESCTRPartialResultBCH2Bob(keyStream, keyStreamMacTag bits.BitSet) AESCTRPartialResult {
	return AESCTRPartialResult{
		Version:           aesCTRPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		KeyStreamBytes:       keyStream.Serialize(),
		KeyStreamMacTagBytes: keyStreamMacTag.Serialize(),
	}
}
