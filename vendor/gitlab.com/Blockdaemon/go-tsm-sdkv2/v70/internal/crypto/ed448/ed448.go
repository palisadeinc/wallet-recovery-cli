package ed448

import (
	"bytes"
	"crypto"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
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
	if l := len(seed); l != SeedSize {
		panic("ed448: bad seed length: " + strconv.Itoa(l))
	}

	s, _ := expandSeed(seed)
	publicKey := ec.Edwards448.G().Multiply(s)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, seed)
	copy(privateKey[57:], publicKey.EncodeCompressed())

	return privateKey
}

func expandSeed(seed []byte) (ec.Scalar, []byte) {
	if l := len(seed); l != SeedSize {
		panic("ed448: bad seed length: " + strconv.Itoa(l))
	}

	h := make([]byte, 114)
	shake := sha3.NewShake256()
	_, _ = shake.Write(seed)
	_, _ = shake.Read(h)

	return setBytesWithClamping(h[:57]), h[57:]
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed448: bad private key length: " + strconv.Itoa(l))
	}

	seed, publicKey := privateKey[:SeedSize], privateKey[SeedSize:]
	s, prefix := expandSeed(seed)

	return sign(s, publicKey, prefix, message)
}

func SignRaw(rawPrivateKey, publicKey, message []byte) []byte {
	if l := len(rawPrivateKey); l != 56 {
		panic("ed448: bad raw private key length: " + strconv.Itoa(l))
	}

	s, err := ec.Edwards448.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		panic("ed448: bad private key: " + err.Error())
	}

	return sign(s, publicKey, random.Bytes(57), message)
}

func sign(s ec.Scalar, publicKey, prefix, message []byte) []byte {

	mh := make([]byte, 114)
	shake := sha3.NewShake256()
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

	signature := make([]byte, SignatureSize)
	copy(signature[:], R.Encode())
	copy(signature[57:], S)
	return signature
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
	if pk.IsPointAtInfinity() {
		return false
	}

	R, err := ec.Edwards448.DecodePoint(sig[:57], false)
	if err != nil {
		return false
	}
	if R.IsPointAtInfinity() {
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
	if S.Equals(ec.Edwards448.Zn().Zero()) {
		return false
	}

	kh := make([]byte, 114)
	shake := sha3.NewShake256()
	_, _ = shake.Write([]byte(dom4(0, defaultContext)))
	_, _ = shake.Write(R.Encode())
	_, _ = shake.Write(publicKey)
	_, _ = shake.Write(message)
	_, _ = shake.Read(kh)
	ec.ReverseSlice(kh)
	k := ec.Edwards448.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(kh))
	if k.Equals(ec.Edwards448.Zn().Zero()) {
		return false
	}

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
