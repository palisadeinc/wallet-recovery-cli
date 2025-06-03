package partialsymmetric

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bch"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/bits"
)

const aesGCMPartialResultVersion = 1

var ErrMessageAuthentication = errors.New("message authentication failed")
var ErrNotEnoughPartialResults = errors.New("not enough partial results")

type AESGCMEncryptPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// For partial result type: Simple
	// All shares hold the output in the clear.
	CiphertextShare []byte
	GCMTagShare     []byte

	// For partial result type: BCH2
	// Player 1 (Bob)'s share contains the outputs (ciphertext, gcm tag) and bch mac tags for each output.
	// Player 0 (Alice)'s share contains bch mac keys for each output.
	CiphertextBytes       []byte
	CiphertextMacTagBytes []byte
	CiphertextMacKeyBytes []byte
	GCMTagBytes           []byte
	GCMTagMacTagBytes     []byte
	GCMTagMacKeyBytes     []byte
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesGCMPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesGCMPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESGCMEncryptPartialResult(protocolID string, threshold, playerIndex int, ciphertextShare, tagShare []byte) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		CiphertextShare: ciphertextShare,
		GCMTagShare:     tagShare,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	ciphertexts map[int][]byte
	gcmTags     map[int][]byte

	// For partial result type: BCH2
	ciphertext       bits.BitSet
	ciphertextMacTag bits.BitSet
	ciphertextMacKey bits.BitSet
	gcmTag           bits.BitSet
	gcmTagMacTag     bits.BitSet
	gcmTagMacKey     bits.BitSet
}

func (e *aesGCMEncryptPartialResultCombiner) Add(partialResult AESGCMEncryptPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesGCMPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.ciphertexts = make(map[int][]byte)
		e.gcmTags = make(map[int][]byte)
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

		for _, v := range e.gcmTags {
			if !bytes.Equal(v, partialResult.GCMTagShare) {
				return fmt.Errorf("partial result mismatch")
			}
		}

		e.ciphertexts[partialResult.PlayerIndex] = partialResult.CiphertextShare
		e.gcmTags[partialResult.PlayerIndex] = partialResult.GCMTagShare

	case BCH2:
		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:

			e.ciphertextMacKey, err = bits.Deserialize(partialResult.CiphertextMacKeyBytes)
			if err != nil {
				return err
			}

			e.gcmTagMacKey, err = bits.Deserialize(partialResult.GCMTagMacKeyBytes)
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

			e.gcmTag, err = bits.Deserialize(partialResult.GCMTagBytes)
			if err != nil {
				return err
			}

			e.gcmTagMacTag, err = bits.Deserialize(partialResult.GCMTagMacTagBytes)
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

func (e *aesGCMEncryptPartialResultCombiner) GCMEncrypt() (ciphertext, gcmTag []byte, err error) {
	switch e.partialResultType {

	case Simple:
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

	case BCH2:

		const alice, bob = 0, 1
		_, hasAlice := e.playerIDs[alice]
		_, hasBob := e.playerIDs[bob]
		if !hasAlice || !hasBob {
			return nil, nil, fmt.Errorf("not enough partial results")
		}

		code, err := bch.NewCode(128, 40)
		if err != nil {
			panic(err)
		}

		if err = checkExtendedBCH(code, e.ciphertext, e.ciphertextMacTag, e.ciphertextMacKey); err != nil {
			return nil, nil, err
		}

		if err = checkExtendedBCH(code, e.gcmTag, e.gcmTagMacTag, e.gcmTagMacKey); err != nil {
			return nil, nil, err
		}

		return e.ciphertext.Bytes(), e.gcmTag.Bytes(), nil

	default:
		panic("unknown partial result type")
	}

}

func NewAESGCMEncryptPartialResultBCH2Alice(ciphertextMacKey, gcmTagMacKey bits.BitSet) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		CiphertextMacKeyBytes: ciphertextMacKey.Serialize(),
		GCMTagMacKeyBytes:     gcmTagMacKey.Serialize(),
	}
}

func NewAESGCMEncryptPartialResultBCH2Bob(ciphertext, ciphertextMacTag, gcmTag, gcmTagMacTag bits.BitSet) AESGCMEncryptPartialResult {
	return AESGCMEncryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		CiphertextBytes:       ciphertext.Serialize(),
		CiphertextMacTagBytes: ciphertextMacTag.Serialize(),
		GCMTagBytes:           gcmTag.Serialize(),
		GCMTagMacTagBytes:     gcmTagMacTag.Serialize(),
	}
}

type AESGCMDecryptPartialResult struct {
	Version           int
	ProtocolID        string
	PlayerIndex       int
	Threshold         int
	PartialResultType PartialResultType

	// For partial result type: Simple
	// All shares hold the output in the clear.
	GCMIsValidShare []byte
	PlaintextShare  []byte

	// For partial result type: BCH2
	// Player 1 (Bob)'s share contains the output (plaintext, isValid) and bch mac tags for each output.
	// Player 0 (Alice)'s share contains bch mac keys for each output.
	PlaintextBytes        []byte
	PlaintextMacTagBytes  []byte
	PlaintextMacKeyBytes  []byte
	GCMIsValidBytes       []byte
	GCMIsValidMacTagBytes []byte
	GCMIsValidMacKeyBytes []byte
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
		Version int
	}
	buf := bytes.NewBuffer(b)
	if err := gob.NewDecoder(buf).Decode(&v); err != nil {
		return err
	}
	if v.Version != aesGCMPartialResultVersion {
		return fmt.Errorf("unsupported partial results version (expected %d, got %d)", aesGCMPartialResultVersion, v.Version)
	}

	buf = bytes.NewBuffer(b)
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewSimpleAESGCMDecryptPartialResult(protocolID string, threshold, playerIndex int, plaintextShare []byte, msgWasAuthentic bool) AESGCMDecryptPartialResult {
	r := AESGCMDecryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		PartialResultType: Simple,
		ProtocolID:        protocolID,
		Threshold:         threshold,
		PlayerIndex:       playerIndex,

		PlaintextShare: plaintextShare,
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
	protocolID        string
	partialResultType PartialResultType
	playerIDs         map[int]int
	threshold         int

	// For partial result type: Simple
	plaintexts map[int][]byte
	isValid    map[int][]byte

	// For partial result type: BCH2
	plaintext        bits.BitSet
	plaintextMacTag  bits.BitSet
	plaintextMacKey  bits.BitSet
	gcmIsValid       bits.BitSet
	gcmIsValidMacTag bits.BitSet
	gcmIsValidMacKey bits.BitSet
}

func (e *aesGCMDecryptPartialResultCombiner) Add(partialResult AESGCMDecryptPartialResult) (err error) {
	if partialResult.Version < 1 || partialResult.Version > aesGCMPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}

	if e.playerIDs == nil {
		e.playerIDs = make(map[int]int)
		e.protocolID = partialResult.ProtocolID
		e.partialResultType = partialResult.PartialResultType
		e.threshold = partialResult.Threshold

		e.plaintexts = make(map[int][]byte)
		e.isValid = make(map[int][]byte)
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

	case BCH2:

		const alice, bob = 0, 1

		switch partialResult.PlayerIndex {
		case alice:

			e.plaintextMacKey, err = bits.Deserialize(partialResult.PlaintextMacKeyBytes)
			if err != nil {
				return err
			}

			e.gcmIsValidMacKey, err = bits.Deserialize(partialResult.GCMIsValidMacKeyBytes)
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

			e.gcmIsValid, err = bits.Deserialize(partialResult.GCMIsValidBytes)
			if err != nil {
				return err
			}

			e.gcmIsValidMacTag, err = bits.Deserialize(partialResult.GCMIsValidMacTagBytes)
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

func (e *aesGCMDecryptPartialResultCombiner) GCMDecrypt() ([]byte, error) {
	switch e.partialResultType {

	case Simple:

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
			return nil, fmt.Errorf("bad bch check plaintext: %w", err)
		}

		if err = checkExtendedBCH(code, e.gcmIsValid, e.gcmIsValidMacTag, e.gcmIsValidMacKey); err != nil {
			return nil, fmt.Errorf("bad bch check isvalid: %w", err)
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

func NewAESGCMDecryptPartialResultBCH2Alice(plaintextMacKey, gcmIsValidMacKey bits.BitSet) AESGCMDecryptPartialResult {
	return AESGCMDecryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       0, // Alice
		Threshold:         1,
		PartialResultType: BCH2,

		PlaintextMacKeyBytes:  plaintextMacKey.Serialize(),
		GCMIsValidMacKeyBytes: gcmIsValidMacKey.Serialize(),
	}
}

func NewAESGCMDecryptPartialResultBCH2Bob(plaintext, plaintextMacTag, gcmIsValid, gcmIsValidMacTag bits.BitSet) AESGCMDecryptPartialResult {
	return AESGCMDecryptPartialResult{
		Version:           aesGCMPartialResultVersion,
		ProtocolID:        "SYM",
		PlayerIndex:       1, // Bob
		Threshold:         1,
		PartialResultType: BCH2,

		PlaintextBytes:        plaintext.Serialize(),
		PlaintextMacTagBytes:  plaintextMacTag.Serialize(),
		GCMIsValidBytes:       gcmIsValid.Serialize(),
		GCMIsValidMacTagBytes: gcmIsValidMacTag.Serialize(),
	}
}
