package partialrsa

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/gob"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/secretshare"
	"hash"
	"math/big"
	"sort"
)

const rsaPartialResultVersion = 1

type RSAPartialResult struct {
	Version     int
	Sharing     secretshare.SharingType
	ProtocolID  string
	PlayerIndex int
	Threshold   int
	E           *big.Int
	N           *big.Int
	Shares      []RSAShare
	HashedInput []byte
}

type RSAShare struct {
	Players []int
	MExpDi  *big.Int
}

func (e *RSAPartialResult) Encode() []byte {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err := enc.Encode(e)
	if err != nil {
		panic(fmt.Sprintf("error encoding partial result: %s", err))
	}
	return buf.Bytes()
}

func (e *RSAPartialResult) Decode(b []byte) error {
	dec := gob.NewDecoder(bytes.NewBuffer(b))
	return dec.Decode(e)
}

func NewRSAPartialResult(protocolID string, playerIndex, threshold int, sharingType secretshare.SharingType, rsaInput, e, n *big.Int, shares []RSAShare) RSAPartialResult {
	return RSAPartialResult{
		Version:     rsaPartialResultVersion,
		Sharing:     sharingType,
		ProtocolID:  protocolID,
		PlayerIndex: playerIndex,
		Threshold:   threshold,
		E:           e,
		N:           n,
		Shares:      shares,
		HashedInput: hashBigInt(rsaInput),
	}
}

func FinalizeRSASignaturePKCS1v15(partialResults []RSAPartialResult, hash crypto.Hash, hashed []byte) ([]byte, error) {
	combiner, err := newRSAPartialResultCombiner(partialResults)
	if err != nil {
		return nil, err
	}
	em, err := combiner.Result()
	if err != nil {
		return nil, err
	}

	if len(hashed) > 0 {
		publicKey := combiner.PublicKey()
		if err = rsa.VerifyPKCS1v15(publicKey, hash, hashed, em); err != nil {
			return nil, fmt.Errorf("signature verification failed: %s", err)
		}
	}

	return em, nil
}

func FinalizeRSASignaturePSS(partialResults []RSAPartialResult, hash crypto.Hash, digest []byte) ([]byte, error) {
	combiner, err := newRSAPartialResultCombiner(partialResults)
	if err != nil {
		return nil, err
	}

	em, err := combiner.Result()
	if err != nil {
		return nil, err
	}

	if len(digest) > 0 {
		publicKey := combiner.PublicKey()
		pssOpts := &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       hash,
		}
		if err = rsa.VerifyPSS(publicKey, hash, digest, em, pssOpts); err != nil {
			return nil, fmt.Errorf("signature verification failed: %s", err)
		}
	}

	return em, nil
}

func FinalizeRSADecryptionPKCS1v15(partialResults []RSAPartialResult) ([]byte, error) {
	combiner, err := newRSAPartialResultCombiner(partialResults)
	if err != nil {
		return nil, err
	}
	em, err := combiner.Result()
	if err != nil {
		return nil, err
	}

	// The rest of this method is about checking and removing PKCS1v15 padding, and it's copied from crypto/rsa/rsa.go

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)
	secondByteIsTwo := subtle.ConstantTimeByteEq(em[1], 2)

	// The remainder of the plaintext must be a string of non-zero random
	// octets, followed by a 0, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the zero.
	//   index: the offset of the first zero byte.
	lookingForIndex := 1

	var index int
	for i := 2; i < len(em); i++ {
		equals0 := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals0, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals0, 0, lookingForIndex)
	}

	// The PS padding must be at least 8 bytes long, and it starts two
	// bytes into em.
	validPS := subtle.ConstantTimeLessOrEq(2+8, index)

	valid := firstByteIsZero & secondByteIsTwo & (^lookingForIndex & 1) & validPS
	index = subtle.ConstantTimeSelect(valid, index+1, 0)
	if valid == 0 {
		return nil, fmt.Errorf("decryption error")
	}
	return em[index:], nil
}

func FinalizeRSADecryptionOAEP(partialResults []RSAPartialResult, hash hash.Hash, label []byte) ([]byte, error) {
	combiner, err := newRSAPartialResultCombiner(partialResults)
	if err != nil {
		return nil, err
	}
	em, err := combiner.Result()
	if err != nil {
		return nil, err
	}

	// The rest of this method is about checking and removing OAEP padding, and it's copied from crypto/rsa/rsa.go

	hash.Write(label)
	lHash := hash.Sum(nil)
	hash.Reset()

	firstByteIsZero := subtle.ConstantTimeByteEq(em[0], 0)

	seed := em[1 : hash.Size()+1]
	db := em[hash.Size()+1:]

	mgf1XOR(seed, hash, db)
	mgf1XOR(db, hash, seed)

	lHash2 := db[0:hash.Size()]

	// We have to validate the plaintext in constant time in order to avoid
	// attacks like: J. Manger. A Chosen Ciphertext Attack on RSA Optimal
	// Asymmetric Encryption Padding (OAEP) as Standardized in PKCS #1
	// v2.0. In J. Kilian, editor, Advances in Cryptology.
	lHash2Good := subtle.ConstantTimeCompare(lHash, lHash2)

	// The remainder of the plaintext must be zero or more 0x00, followed
	// by 0x01, followed by the message.
	//   lookingForIndex: 1 iff we are still looking for the 0x01
	//   index: the offset of the first 0x01 byte
	//   invalid: 1 iff we saw a non-zero byte before the 0x01.
	var lookingForIndex, index, invalid int
	lookingForIndex = 1
	rest := db[hash.Size():]

	for i := 0; i < len(rest); i++ {
		equals0 := subtle.ConstantTimeByteEq(rest[i], 0)
		equals1 := subtle.ConstantTimeByteEq(rest[i], 1)
		index = subtle.ConstantTimeSelect(lookingForIndex&equals1, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(equals1, 0, lookingForIndex)
		invalid = subtle.ConstantTimeSelect(lookingForIndex&^equals0, 1, invalid)
	}

	if firstByteIsZero&lHash2Good&^invalid&^lookingForIndex != 1 {
		return nil, fmt.Errorf("decryption error")
	}

	return rest[index+1:], nil
}

func FinalizeRSADecryptionRaw(partialResults []RSAPartialResult) ([]byte, error) {
	combiner, err := newRSAPartialResultCombiner(partialResults)
	if err != nil {
		return nil, err
	}
	return combiner.Result()
}

type rsaPartialResultCombiner struct {
	threshold   int
	hashedInput []byte
	e           *big.Int
	n           *big.Int
	shares      map[string][]RSAShare
}

func newRSAPartialResultCombiner(partialResults []RSAPartialResult) (*rsaPartialResultCombiner, error) {
	var combiner rsaPartialResultCombiner
	for _, partialResult := range partialResults {
		err := combiner.Add(partialResult)
		if err != nil {
			return nil, err
		}
	}

	// Validate n

	if combiner.n == nil {
		return nil, fmt.Errorf("missing public modulus")
	}
	nLen := (combiner.n.BitLen() + 7) / 8
	if nLen < 11 {
		return nil, fmt.Errorf("public modulus too small")
	}

	// Validate e

	if combiner.e == nil {
		return nil, fmt.Errorf("missing public exponent")
	}
	e := combiner.e.Int64()
	if e < 2 {
		return nil, fmt.Errorf("public exponent too small")
	}
	if e > 1<<31-1 {
		return nil, fmt.Errorf("public exponent too large")
	}

	return &combiner, nil
}

func (e *rsaPartialResultCombiner) Add(partialResult RSAPartialResult) error {
	if partialResult.Version < 1 || partialResult.Version > rsaPartialResultVersion {
		return fmt.Errorf("unsupported partial result version: %d", partialResult.Version)
	}
	
	if partialResult.ProtocolID != "RSA" {
		return fmt.Errorf("unsupported protocol for RSA: %s", partialResult.ProtocolID)
	}

	if partialResult.Sharing != secretshare.ADN06Sharing {
		return fmt.Errorf("unsupported sharing type: %s", partialResult.Sharing.String())
	}

	if len(e.shares) == 0 {
		e.threshold = partialResult.Threshold
		e.hashedInput = partialResult.HashedInput
		e.e = partialResult.E
		e.n = partialResult.N
		e.shares = map[string][]RSAShare{}
	} else {
		if e.threshold != partialResult.Threshold {
			return fmt.Errorf("threshold mismatch")
		}
		if !bytes.Equal(e.hashedInput, partialResult.HashedInput) {
			return fmt.Errorf("input hash mismatch")
		}
		if e.e.Cmp(partialResult.E) != 0 {
			return fmt.Errorf("public key e mismatch")
		}
		if e.n.Cmp(partialResult.N) != 0 {
			return fmt.Errorf("public key n mismatch")
		}
	}

	sortedPlayers := make([]int, e.threshold+1)
	for _, share := range partialResult.Shares {
		if len(share.Players) != e.threshold+1 {
			return fmt.Errorf("wrong number of players (%d) for threshold %d", len(share.Players), e.threshold)
		}
		copy(sortedPlayers, share.Players)
		sort.Ints(sortedPlayers)
		mapKey := fmt.Sprintf("%v", sortedPlayers)
		shareArray := e.shares[mapKey]
		shareArray = append(shareArray, share)
		e.shares[mapKey] = shareArray
	}

	return nil
}

func (e *rsaPartialResultCombiner) PublicKey() *rsa.PublicKey {
	return &rsa.PublicKey{
		N: e.n,
		E: int(e.e.Int64()),
	}
}

func (e *rsaPartialResultCombiner) Result() ([]byte, error) {
	// Find exactly t+1 shares from the same set of players

	var shares []RSAShare
	for _, s := range e.shares {
		if len(s) == e.threshold+1 {
			shares = s
			break
		}
	}
	if len(shares) == 0 {
		return nil, fmt.Errorf("not enough partial results or the partial results are from the wrong players")
	}

	// Combine the partial results and check that they correspond to the original input

	em := big.NewInt(1)
	for _, s := range shares {
		em.Mul(em, s.MExpDi)
		em.Mod(em, e.n)
	}
	expectedInput := new(big.Int).Exp(em, e.e, e.n)
	if !bytes.Equal(hashBigInt(expectedInput), e.hashedInput) {
		return nil, fmt.Errorf("unexpected result from players: %v", shares[0].Players)
	}

	b := make([]byte, (e.n.BitLen()+7)/8)
	em.FillBytes(b)
	return b, nil
}

func hashBigInt(v *big.Int) []byte {
	h := sha256.New()
	_, _ = h.Write(v.Bytes())
	return h.Sum(nil)
}

// mgf1XOR XORs the bytes in out with a mask generated using the MGF1 function
// specified in PKCS #1 v2.1.
func mgf1XOR(out []byte, hash hash.Hash, seed []byte) {
	var counter [4]byte
	var digest []byte

	done := 0
	for done < len(out) {
		hash.Write(seed)
		hash.Write(counter[0:4])
		digest = hash.Sum(digest[:0])
		hash.Reset()

		for i := 0; i < len(digest) && done < len(out); i++ {
			out[done] ^= digest[i]
			done++
		}
		incCounter(&counter)
	}
}

// incCounter increments a four byte, big-endian counter.
func incCounter(c *[4]byte) {
	if c[3]++; c[3] != 0 {
		return
	}
	if c[2]++; c[2] != 0 {
		return
	}
	if c[1]++; c[1] != 0 {
		return
	}
	c[0]++
}
