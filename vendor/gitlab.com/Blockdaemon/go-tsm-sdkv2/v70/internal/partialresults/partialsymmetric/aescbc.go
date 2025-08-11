package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
)

// Version 1: Initial
const aesCBCEncryptPartialResultVersionSimple = 1

// Version 1: Initial
const aesCBCDecryptPartialResultVersionSimple = 1

// Version 1: Initial
// Version 2: Changed mac key structure
const aesCBCDecryptPartialResultVersionMAC2 = 2

// Version 1: Initial
// Version 2: Changed mac key structure
const aesCBCEncryptPartialResultVersionMAC2 = 2

type AESCBCEncryptPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// Fields for partial result type: Simple, version 1
	// All shares hold the output in the clear.
	CiphertextShare []byte

	// Fields for partial result type: MAC2, version 2
	// Player 1 (Bob)'s share consists of output (ciphertext) and information theoretical mac tag on the output.
	// Player 0 (Alice)'s share contains the information theoretical mac key for the output.
	CiphertextBytes       []byte
	CiphertextMacTagBytes []byte
	CiphertextMacKeyBytes []byte
}

func (e *AESCBCEncryptPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESCBCEncryptPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > aesCBCEncryptPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesCBCEncryptPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCBCEncryptPartialResult(protocolID string, threshold, playerIndex int, ciphertextShare []byte) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesCBCEncryptPartialResultVersionSimple,

		Threshold:       threshold,
		PlayerIndex:     playerIndex,
		CiphertextShare: ciphertextShare,
	}
}

func FinalizeAESCBCEncrypt(partialResults ...AESCBCEncryptPartialResult) (ciphertext []byte, err error) {
	var combiner aesCBCEncryptPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.CBCEncrypt()
}

type aesCBCEncryptPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	ciphertexts map[int][]byte

	// For partial result type: MAC2, version 2
	ciphertext       bits.BitSet
	ciphertextMacTag bits.BitSet
	ciphertextMacKey bits.BitSet
}

func (e *aesCBCEncryptPartialResultCombiner) Add(partialResult AESCBCEncryptPartialResult) (err error) {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.ciphertexts = make(map[int][]byte)
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
		for _, v := range e.ciphertexts {
			if !bytes.Equal(v, partialResult.CiphertextShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.ciphertexts[partialResult.PlayerIndex] = partialResult.CiphertextShare

	case MAC2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:
			e.ciphertextMacKey, err = bits.Deserialize(partialResult.CiphertextMacKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.ciphertext, err = bits.Deserialize(partialResult.CiphertextBytes)
			if err != nil {
				return err
			}

			e.ciphertextMacTag, err = bits.Deserialize(partialResult.CiphertextMacTagBytes)
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

func (e *aesCBCEncryptPartialResultCombiner) CBCEncrypt() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesCBCEncryptPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionSimple, e.version)
		}

		if len(e.ciphertexts) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.ciphertexts {
			return v, nil
		}

	case MAC2:
		if e.version != aesCBCEncryptPartialResultVersionMAC2 {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionMAC2, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		if err := checkInfoMac(e.ciphertext, e.ciphertextMacTag, e.ciphertextMacKey); err != nil {
			return nil, err
		}

		return e.ciphertext.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCBCEncryptPartialResultMAC2Alice(protocolID string, keyStreamMacKey bits.BitSet) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		ProtocolID:            protocolID,
		PartialResultType:     MAC2,
		Version:               aesCBCEncryptPartialResultVersionMAC2,
		PlayerIndex:           0, // Alice
		Threshold:             1,
		CiphertextMacKeyBytes: keyStreamMacKey.Serialize(),
	}
}

func NewAESCBCEncryptPartialResultMAC2Bob(protocolID string, ciphertext, ciphertextMacTag bits.BitSet) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		ProtocolID:            protocolID,
		PartialResultType:     MAC2,
		Version:               aesCBCEncryptPartialResultVersionMAC2,
		PlayerIndex:           1, // Bob
		Threshold:             1,
		CiphertextBytes:       ciphertext.Serialize(),
		CiphertextMacTagBytes: ciphertextMacTag.Serialize(),
	}
}

type AESCBCDecryptPartialResult struct {
	ProtocolID        string
	Version           int
	PartialResultType PartialResultType

	PlayerIndex int
	Threshold   int

	// For partial result type: Simple, version 1
	// All shares hold the output in the clear.
	PlaintextShare []byte

	// For partial result type: MAC2, version 2
	// Player 1 (Bob)'s share consists of key stream and key stream mac tag and player 1 (Alice)'s share contains key
	// stream mac key.
	PlaintextBytes       []byte
	PlaintextMacTagBytes []byte
	PlaintextMacKeyBytes []byte
}

func (e *AESCBCDecryptPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESCBCDecryptPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > aesCBCDecryptPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesCBCDecryptPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCBCDecryptPartialResult(protocolID string, threshold, playerIndex int, plaintextShare []byte) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesCBCDecryptPartialResultVersionSimple,
		PlayerIndex:       playerIndex,
		Threshold:         threshold,
		PlaintextShare:    plaintextShare,
	}
}

func FinalizeAESCBCDecrypt(partialResults ...AESCBCDecryptPartialResult) (plaintext []byte, err error) {
	var combiner aesCBCDecryptPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.CBCDecrypt()
}

type aesCBCDecryptPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1

	plaintexts map[int][]byte

	// For partial result type: MAC2, version 2

	plaintext       bits.BitSet
	plaintextMacTag bits.BitSet
	plaintextMacKey bits.BitSet
}

func (e *aesCBCDecryptPartialResultCombiner) Add(partialResult AESCBCDecryptPartialResult) (err error) {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.plaintexts = make(map[int][]byte)
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
		for _, v := range e.plaintexts {
			if !bytes.Equal(v, partialResult.PlaintextShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.plaintexts[partialResult.PlayerIndex] = partialResult.PlaintextShare

	case MAC2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:
			e.plaintextMacKey, err = bits.Deserialize(partialResult.PlaintextMacKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.plaintext, err = bits.Deserialize(partialResult.PlaintextBytes)
			if err != nil {
				return err
			}

			e.plaintextMacTag, err = bits.Deserialize(partialResult.PlaintextMacTagBytes)
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

func (e *aesCBCDecryptPartialResultCombiner) CBCDecrypt() (plaintext []byte, err error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesCBCDecryptPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionSimple, e.version)
		}

		if len(e.plaintexts) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.plaintexts {
			return v, nil
		}
	case MAC2:
		if e.version != aesCBCDecryptPartialResultVersionMAC2 {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionSimple, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		if err := checkInfoMac(e.plaintext, e.plaintextMacTag, e.plaintextMacKey); err != nil {
			return nil, err
		}

		return e.plaintext.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCBCDecryptPartialResultMAC2Alice(protocolID string, plaintextMacKey bits.BitSet) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesCBCDecryptPartialResultVersionMAC2,

		PlayerIndex:          0, // Alice
		Threshold:            1,
		PlaintextMacKeyBytes: plaintextMacKey.Serialize(),
	}
}

func NewAESCBCDecryptPartialResultMAC2Bob(protocolID string, plaintext, plaintextMacTag bits.BitSet) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesCBCDecryptPartialResultVersionMAC2,

		PlayerIndex:          1, // Bob
		Threshold:            1,
		PlaintextBytes:       plaintext.Serialize(),
		PlaintextMacTagBytes: plaintextMacTag.Serialize(),
	}
}
