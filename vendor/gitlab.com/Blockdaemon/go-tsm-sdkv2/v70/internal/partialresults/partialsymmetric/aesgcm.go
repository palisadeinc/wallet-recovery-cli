package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
)

var ErrMessageAuthentication = errors.New("message authentication failed")
var ErrNotEnoughPartialResults = errors.New("not enough partial results")

// Version 1: Initial
const aesGCMEncryptPartialResultVersionSimple = 1

// Version 1: Initial
const aesGCMDecryptPartialResultVersionSimple = 1

// Version 1: Initial
// Version 2: Change mac key structure and use single output mac tag for all output
const aesGCMEncryptPartialResultVersionMAC2 = 2

// Version 1: Initial
// Version 2: Change mac key structure and use single output mac tag for all output
const aesGCMDecryptPartialResultVersionMAC2 = 2

type AESGCMEncryptPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// For partial result type: Simple, version 1
	// All shares hold the output in the clear.
	CiphertextShare []byte
	GCMTagShare     []byte

	// For partial result type: MAC2, version 2
	// Player 0 (Alice)'s share contains a mac key for the concatenated output.
	// Player 1 (Bob)'s share contains the outputs (ciphertext, gcm tag) and a mac tag for the concatenated output.
	CiphertextBytes   []byte
	GCMTagBytes       []byte
	OutputMACKeyBytes []byte
	OutputMACTagBytes []byte
}

func (e *AESGCMEncryptPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESGCMEncryptPartialResult) Decode(b []byte) error {
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
	case MAC2:
		if v.Version < 1 || v.Version > aesGCMEncryptPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESGCMEncryptPartialResult(protocolID string, threshold, playerIndex int, ciphertextShare, tagShare []byte) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesGCMEncryptPartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		CiphertextShare:   ciphertextShare,
		GCMTagShare:       tagShare,
	}
}

func FinalizeAESGCMEncrypt(partialResults ...AESGCMEncryptPartialResult) (ciphertext, tag []byte, err error) {
	var combiner aesGCMEncryptPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, nil, err
		}
	}
	return combiner.GCMEncrypt()
}

type aesGCMEncryptPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	ciphertexts map[int][]byte
	gcmTags     map[int][]byte

	// For partial result type: MAC2, version 2
	ciphertext   bits.BitSet
	gcmTag       bits.BitSet
	outputMacKey bits.BitSet
	outputMacTag bits.BitSet
}

func (e *aesGCMEncryptPartialResultCombiner) Add(partialResult AESGCMEncryptPartialResult) (err error) {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.ciphertexts = make(map[int][]byte)
		e.gcmTags = make(map[int][]byte)
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

		for _, v := range e.gcmTags {
			if !bytes.Equal(v, partialResult.GCMTagShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.ciphertexts[partialResult.PlayerIndex] = partialResult.CiphertextShare
		e.gcmTags[partialResult.PlayerIndex] = partialResult.GCMTagShare

	case MAC2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:
			e.outputMacKey, err = bits.Deserialize(partialResult.OutputMACKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.ciphertext, err = bits.Deserialize(partialResult.CiphertextBytes)
			if err != nil {
				return err
			}

			e.outputMacTag, err = bits.Deserialize(partialResult.OutputMACTagBytes)
			if err != nil {
				return err
			}

			e.gcmTag, err = bits.Deserialize(partialResult.GCMTagBytes)
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

func (e *aesGCMEncryptPartialResultCombiner) GCMEncrypt() (ciphertext, gcmTag []byte, err error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesGCMEncryptPartialResultVersionSimple {
			return nil, nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionSimple, e.version)
		}

		if len(e.ciphertexts) < e.threshold+1 {
			return nil, nil, fmt.Errorf("not enough partial results")
		}

		for _, c := range e.ciphertexts {
			ciphertext = c
			break
		}

		for _, t := range e.gcmTags {
			gcmTag = t
			break
		}

		return ciphertext, gcmTag, nil

	case MAC2:
		if e.version != aesGCMEncryptPartialResultVersionMAC2 {
			return nil, nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionMAC2, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, nil, fmt.Errorf("not enough partial results")
		}

		totalOutput := bits.Concat(e.ciphertext, e.gcmTag)

		if err := checkInfoMac(totalOutput, e.outputMacTag, e.outputMacKey); err != nil {
			return nil, nil, err
		}

		return e.ciphertext.Bytes(), e.gcmTag.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

}

func NewAESGCMEncryptPartialResultMAC2Alice(protocolID string, outputMacKey bits.BitSet) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesGCMEncryptPartialResultVersionMAC2,
		PlayerIndex:       0, // Alice
		Threshold:         1,
		OutputMACKeyBytes: outputMacKey.Serialize(),
	}
}

func NewAESGCMEncryptPartialResultMAC2Bob(protocolID string, ciphertext, gcmTag, outputMacTag bits.BitSet) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesGCMEncryptPartialResultVersionMAC2,
		PlayerIndex:       1, // Bob
		Threshold:         1,
		CiphertextBytes:   ciphertext.Serialize(),
		GCMTagBytes:       gcmTag.Serialize(),
		OutputMACTagBytes: outputMacTag.Serialize(),
	}
}

type AESGCMDecryptPartialResult struct {
	ProtocolID        string
	PartialResultType PartialResultType
	Version           int

	PlayerIndex int
	Threshold   int

	// For partial result type: Simple, version 1
	// All shares hold the output in the clear.
	GCMIsValidShare []byte
	PlaintextShare  []byte

	// For partial result type: MAC2, version 2
	// Player 1 (Bob)'s share contains the output (plaintext, isValid) and a mac tag for the concatenated output.
	// Player 0 (Alice)'s share contains a mac key for the concatenated output.
	PlaintextBytes    []byte
	GCMIsValidBytes   []byte
	OutputMACKeyBytes []byte
	OutputMACTagBytes []byte
}

func (e *AESGCMDecryptPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *AESGCMDecryptPartialResult) Decode(b []byte) error {
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
		if v.Version < 1 || v.Version > aesGCMDecryptPartialResultVersionSimple {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	case MAC2:
		if v.Version < 1 || v.Version > aesGCMDecryptPartialResultVersionMAC2 {
			return fmt.Errorf("unsupported partial result version: %d", v.Version)
		}
	default:
		return fmt.Errorf("unknown partial result type: %s", v.PartialResultType.String())
	}

	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESGCMDecryptPartialResult(protocolID string, threshold, playerIndex int, plaintextShare []byte, msgWasAuthentic bool) AESGCMDecryptPartialResult {
	r := AESGCMDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: Simple,
		Version:           aesGCMDecryptPartialResultVersionSimple,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,
		PlaintextShare:    plaintextShare,
	}
	if msgWasAuthentic {
		r.GCMIsValidShare = []byte{1}
	} else {
		r.GCMIsValidShare = []byte{0}
	}

	return r
}

// FinalizeAESGCMDecrypt will return ErrMessageAuthentication if the AES-GCM authentication tag was not
// valid with respect to the provided ciphertext and additional data.
func FinalizeAESGCMDecrypt(partialResults ...AESGCMDecryptPartialResult) (plaintext []byte, err error) {
	var combiner aesGCMDecryptPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}
	return combiner.GCMDecrypt()
}

type aesGCMDecryptPartialResultCombiner struct {
	partialResultType PartialResultType
	version           int

	playerIDs map[int]int
	threshold int

	// For partial result type: Simple, version 1
	plaintexts map[int][]byte
	isValid    map[int][]byte

	// For partial result type: MAC2, version 2
	plaintext    bits.BitSet
	gcmIsValid   bits.BitSet
	outputMacKey bits.BitSet
	outputMacTag bits.BitSet
}

func (e *aesGCMDecryptPartialResultCombiner) Add(partialResult AESGCMDecryptPartialResult) (err error) {
	if e.playerIDs == nil {
		e.partialResultType = partialResult.PartialResultType
		e.version = partialResult.Version
		e.playerIDs = make(map[int]int)
		e.threshold = partialResult.Threshold
		e.plaintexts = make(map[int][]byte)
		e.isValid = make(map[int][]byte)
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
		for _, p := range e.plaintexts {
			if !bytes.Equal(p, partialResult.PlaintextShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		for _, a := range e.isValid {
			if !bytes.Equal(a, partialResult.GCMIsValidShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.plaintexts[partialResult.PlayerIndex] = partialResult.PlaintextShare
		e.isValid[partialResult.PlayerIndex] = partialResult.GCMIsValidShare

	case MAC2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:
			e.outputMacKey, err = bits.Deserialize(partialResult.OutputMACKeyBytes)
			if err != nil {
				return err
			}

		case bob:
			e.plaintext, err = bits.Deserialize(partialResult.PlaintextBytes)
			if err != nil {
				return err
			}

			e.gcmIsValid, err = bits.Deserialize(partialResult.GCMIsValidBytes)
			if err != nil {
				return err
			}

			e.outputMacTag, err = bits.Deserialize(partialResult.OutputMACTagBytes)
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

func (e *aesGCMDecryptPartialResultCombiner) GCMDecrypt() ([]byte, error) {
	switch e.partialResultType {
	case Simple:
		if e.version != aesGCMDecryptPartialResultVersionSimple {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionSimple, e.version)
		}

		if len(e.plaintexts) < e.threshold+1 {
			return nil, ErrNotEnoughPartialResults
		}

		for _, a := range e.isValid {
			if a[0] == 0 {
				return nil, ErrMessageAuthentication
			}
			break
		}

		for _, p := range e.plaintexts {
			return p, nil
		}

	case MAC2:
		if e.version != aesGCMDecryptPartialResultVersionMAC2 {
			return nil, fmt.Errorf("unsupported partial result version (expected %d, got %d)", aesGCMEncryptPartialResultVersionMAC2, e.version)
		}

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, fmt.Errorf("not enough partial results")
		}

		totalOutput := bits.Concat(e.plaintext, e.gcmIsValid)
		if err := checkInfoMac(totalOutput, e.outputMacTag, e.outputMacKey); err != nil {
			return nil, err
		}

		valid := e.gcmIsValid.Bytes()
		if valid[0] != 1 {
			return nil, ErrMessageAuthentication
		}

		return e.plaintext.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

	panic("unreachable")
}

func NewAESGCMDecryptPartialResultMAC2Alice(protocolID string, outputMacKey bits.BitSet) AESGCMDecryptPartialResult {
	return AESGCMDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesGCMDecryptPartialResultVersionMAC2,
		PlayerIndex:       0, // Alice
		Threshold:         1,
		OutputMACKeyBytes: outputMacKey.Serialize(),
	}
}

func NewAESGCMDecryptPartialResultMAC2Bob(protocolID string, plaintext, gcmIsValid, outputMacTag bits.BitSet) AESGCMDecryptPartialResult {
	return AESGCMDecryptPartialResult{
		ProtocolID:        protocolID,
		PartialResultType: MAC2,
		Version:           aesGCMDecryptPartialResultVersionMAC2,
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PlaintextBytes:    plaintext.Serialize(),
		GCMIsValidBytes:   gcmIsValid.Serialize(),
		OutputMACTagBytes: outputMacTag.Serialize(),
	}
}
