package zilliqaschnorr

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"io"
	"math/big"
	"strconv"
)

const (
	PublicKeySize  = 33
	PrivateKeySize = 65
	SignatureSize  = 64
)

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

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey) {
	if rand == nil {
		rand = random.Reader
	}

	x := ec.Secp256k1.Zn().NewScalarFromReader(rand)
	Y := ec.Secp256k1.G().Multiply(x)

	publicKey := Y.EncodeCompressed()
	privateKey := append(x.Encode(), publicKey...)

	return publicKey, privateKey
}

func Sign(privateKey, message []byte) []byte {
	if len(privateKey) != PrivateKeySize {
		panic("zilliqaschnorr: bad private key length: %d" + strconv.Itoa(len(privateKey)))
	}

	return sign(privateKey[:32], message, ec.Secp256k1.Zn().NewRandomScalar())
}

func SignRaw(rawPrivateKey, message []byte) []byte {
	if len(rawPrivateKey) != 32 {
		panic("zilliqaschnorr: bad raw private key length: %d" + strconv.Itoa(len(rawPrivateKey)))
	}

	return sign(rawPrivateKey, message, ec.Secp256k1.Zn().NewRandomScalar())
}

func sign(rawPrivateKey, message []byte, k ec.Scalar) []byte {
	zn := ec.Secp256k1.Zn()
	privateKeyScalar, err := zn.DecodeScalar(rawPrivateKey)
	if err != nil || privateKeyScalar.Equals(zn.Zero()) {
		panic("zilliqaschnorr: bad private key")
	}
	publicKey := ec.Secp256k1.G().Multiply(privateKeyScalar)

	// Q = k*G
	if k.Equals(zn.Zero()) {
		panic("zilliqaschnorr: k is zero")
	}
	Q := ec.Secp256k1.G().Multiply(k)

	r := msgHash(Q.EncodeCompressed(), publicKey.EncodeCompressed(), message)
	if r.Equals(zn.Zero()) {
		panic("zilliqaschnorr: r is zero")
	}

	// s = k - r * privateKey
	s := k.Subtract(r.Multiply(privateKeyScalar))
	if s.Equals(zn.Zero()) {
		panic("zilliqaschnorr: s is zero")
	}

	return append(r.Encode(), s.Encode()...)
}

func Verify(publicKey, message, sig []byte) bool {
	if len(publicKey) != PublicKeySize {
		panic("zilliqaschnorr: bad public key length" + strconv.Itoa(len(publicKey)))
	}

	if len(sig) != SignatureSize {
		return false
	}

	publicKeyPoint, err := ec.Secp256k1.DecodePoint(publicKey, true)
	if err != nil {
		return false
	}
	if publicKeyPoint.IsPointAtInfinity() {
		return false
	}

	zn := ec.Secp256k1.Zn()
	r, err := zn.DecodeScalar(sig[:32])
	if err != nil {
		return false
	}
	if r.Equals(zn.Zero()) {
		return false
	}

	s, err := zn.DecodeScalar(sig[32:])
	if err != nil {
		return false
	}
	if s.Equals(zn.Zero()) {
		return false
	}

	Q := publicKeyPoint.MultiplyVarTime(r).Add(ec.Secp256k1.G().Multiply(s))
	return msgHash(Q.EncodeCompressed(), publicKeyPoint.EncodeCompressed(), message).Equals(r)
}

func msgHash(Q []byte, pubKey []byte, msg []byte) ec.Scalar {
	h := sha256.New()
	h.Write(Q)
	h.Write(pubKey)
	h.Write(msg)

	r := new(big.Int).SetBytes(h.Sum(nil))
	return ec.Secp256k1.Zn().NewScalarWithModularReduction(r)
}
