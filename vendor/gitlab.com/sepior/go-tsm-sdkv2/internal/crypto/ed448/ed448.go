package ed448

import (
	"bytes"
	"crypto"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/random"
	"golang.org/x/crypto/sha3"
	"io"
	"math/big"
	"strconv"
)

const (
	PublicKeySize  = 57
	PrivateKeySize = 114
	SignatureSize  = 114
	SeedSize       = 57
)

const defaultContext = ""

type PublicKey []byte

func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}

type PrivateKey []byte

func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[len(priv)-PublicKeySize:])
	return PublicKey(publicKey)
}

func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(priv, xx)
}

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = random.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[57:])

	return publicKey, privateKey, nil
}

func NewKeyFromSeed(seed []byte) PrivateKey {
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed448: bad seed length: " + strconv.Itoa(l))
	}

	h := make([]byte, 114)
	shake := sha3.NewShake256()
	_, _ = shake.Write(seed)
	_, _ = shake.Read(h)

	s := setBytesWithClamping(h[:57])
	publicKey := ec.Edwards448.G().Multiply(s)

	copy(privateKey, seed)
	copy(privateKey[57:], publicKey.Encode())
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	signature := make([]byte, SignatureSize)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed448: bad private key length: " + strconv.Itoa(l))
	}

	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]
	shake := sha3.NewShake256()

	h := make([]byte, 114)
	shake.Reset()
	_, _ = shake.Write(seed)
	_, _ = shake.Read(h)

	s := setBytesWithClamping(h[:57])
	prefix := h[57:]

	mh := make([]byte, 114)
	shake.Reset()
	_, _ = shake.Write([]byte(dom4(0, defaultContext)))
	_, _ = shake.Write(prefix)
	_, _ = shake.Write(message)
	_, _ = shake.Read(mh)
	ec.ReverseSlice(mh)
	r := ec.Edwards448.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(mh))

	R := ec.Edwards448.G().Multiply(r)

	kh := make([]byte, 114)
	shake.Reset()
	_, _ = shake.Write([]byte(dom4(0, defaultContext)))
	_, _ = shake.Write(R.Encode())
	_, _ = shake.Write(publicKey)
	_, _ = shake.Write(message)
	_, _ = shake.Read(kh)
	ec.ReverseSlice(kh)
	k := ec.Edwards448.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(kh))

	S := k.Multiply(s).Add(r).Encode()
	ec.ReverseSlice(S)

	copy(signature[:], R.Encode())
	copy(signature[57:], S)
}

func Verify(publicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed448: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize {
		return false
	}

	pk, err := ec.Edwards448.DecodePoint(publicKey, false)
	if err != nil {
		return false
	}

	R, err := ec.Edwards448.DecodePoint(sig[:57], false)
	if err != nil {
		return false
	}

	b := make([]byte, 57)
	copy(b, sig[57:])
	ec.ReverseSlice(b)
	sB := new(big.Int).SetBytes(b[:])
	if sB.Cmp(ec.Edwards448.Zn().Modulus()) >= 0 {
		return false
	}
	S := ec.Edwards448.Zn().NewScalarWithModularReduction(sB)

	kh := make([]byte, 114)
	shake := sha3.NewShake256()
	_, _ = shake.Write([]byte(dom4(0, defaultContext)))
	_, _ = shake.Write(R.Encode())
	_, _ = shake.Write(publicKey)
	_, _ = shake.Write(message)
	_, _ = shake.Read(kh)
	ec.ReverseSlice(kh)
	k := ec.Edwards448.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(kh))

	return ec.Edwards448.G().MultiplyVarTime(S).Equals(pk.MultiplyVarTime(k).Add(R))
}

func dom4(x byte, y string) string {
	return fmt.Sprintf("%s%s%s%s", "SigEd448", string(x), string(byte(len(y))), y)
}

func setBytesWithClamping(x []byte) ec.Scalar {
	x[0] = x[0] & 252
	x[55] = x[55] | 128
	x[56] = 0
	ec.ReverseSlice(x)

	return ec.Edwards448.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(x))
}
