package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bch"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bits"
)

const aesCBCPartialResultVersion = 1

type AESCBCEncryptPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// Fields for partial result type: Simple
	// All shares hold the output in the clear.
	CiphertextShare []byte

	// Fields for  partial result type: BCH2
	// Player 1 (Bob)'s share consists of output (ciphertext) and bch mac tag on the output.
	// Player 0 (Alice)'s share contains the bch mac key for the output.
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesCBCPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesCBCPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCBCEncryptPartialResult(protocolID string, threshold, playerIndex int, ciphertextShare []byte) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	ciphertexts map[int][]byte

	// For partial result type: BCH2
	ciphertext       bits.BitSet
	ciphertextMacTag bits.BitSet
	ciphertextMacKey bits.BitSet
}

func (e *aesCBCEncryptPartialResultCombiner) Add(partialResult AESCBCEncryptPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesCBCPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.ciphertexts = make(map[int][]byte)
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
		for _, v := range e.ciphertexts {
			if !bytes.Equal(v, partialResult.CiphertextShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.ciphertexts[partialResult.PlayerIndex] = partialResult.CiphertextShare

	case BCH2:
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
			return fmt.Errorf("bch2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil
}

func (e *aesCBCEncryptPartialResultCombiner) CBCEncrypt() ([]byte, error) {
	switch e.partialResultType {

	case Simple:

		if len(e.ciphertexts) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.ciphertexts {
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

		if err = checkExtendedBCH(code, e.ciphertext, e.ciphertextMacTag, e.ciphertextMacKey); err != nil {
			return nil, err
		}

		return e.ciphertext.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCBCEncryptPartialResultXORBCH2Alice(keyStreamMacKey bits.BitSet) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		CiphertextMacKeyBytes: keyStreamMacKey.Serialize(),
	}
}

func NewAESCBCEncryptPartialResultXORBCH2Bob(ciphertext, ciphertextMacTag bits.BitSet) AESCBCEncryptPartialResult {
	return AESCBCEncryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		CiphertextBytes:       ciphertext.Serialize(),
		CiphertextMacTagBytes: ciphertextMacTag.Serialize(),
	}
}

type AESCBCDecryptPartialResult struct {
	Version     int
	ProtocolID  string
	PlayerIndex int
	Threshold   int

	PartialResultType PartialResultType

	// For partial result type: Simple
	// All shares hold the output in the clear.
	PlaintextShare []byte

	// For partial result type: BCH2
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesCBCPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesCBCPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESCBCDecryptPartialResult(protocolID string, threshold, playerIndex int, plaintextShare []byte) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple

	plaintexts map[int][]byte

	// For partial result type: BCH2

	plaintext       bits.BitSet
	plaintextMacTag bits.BitSet
	plaintextMacKey bits.BitSet
}

func (e *aesCBCDecryptPartialResultCombiner) Add(partialResult AESCBCDecryptPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesCBCPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.plaintexts = make(map[int][]byte)
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

		for _, v := range e.plaintexts {
			if !bytes.Equal(v, partialResult.PlaintextShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}
		e.plaintexts[partialResult.PlayerIndex] = partialResult.PlaintextShare

	case BCH2:
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
			return fmt.Errorf("xorbch2: invalid player index %d", partialResult.PlayerIndex)
		}

	default:
		return fmt.Errorf("unsupported partial result type: %s", partialResult.PartialResultType.String())
	}

	return nil

}

func (e *aesCBCDecryptPartialResultCombiner) CBCDecrypt() (plaintext []byte, err error) {
	switch e.partialResultType {

	case Simple:

		if len(e.plaintexts) < e.threshold+1 {
			return nil, fmt.Errorf("not enough partial results")
		}
		for _, v := range e.plaintexts {
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

		if err = checkExtendedBCH(code, e.plaintext, e.plaintextMacTag, e.plaintextMacKey); err != nil {
			return nil, err
		}

		return e.plaintext.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESCBCDecryptPartialResultBCH2Alice(plaintextMacKey bits.BitSet) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		PlaintextMacKeyBytes: plaintextMacKey.Serialize(),
	}
}

func NewAESCBCDecryptPartialResultBCH2Bob(plaintext, plaintextMacTag bits.BitSet) AESCBCDecryptPartialResult {
	return AESCBCDecryptPartialResult{
		Version:           aesCBCPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		PlaintextBytes:       plaintext.Serialize(),
		PlaintextMacTagBytes: plaintextMacTag.Serialize(),
	}
}
