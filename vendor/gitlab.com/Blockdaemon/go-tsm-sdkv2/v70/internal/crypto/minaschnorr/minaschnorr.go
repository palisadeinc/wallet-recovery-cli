package minaschnorr

import (
	"bytes"
	"crypto"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/crypto/minaschnorr/internal/poseidon"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"golang.org/x/crypto/blake2b"
	"io"
	"strconv"
)

var (
	fp = ec.PallasMinaFp
	fq = ec.PallasMina.Zn()
)

const (
	PublicKeySize  = 32
	PrivateKeySize = 64
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

	x := ec.PallasMina.Zn().NewScalarFromReader(rand)
	Y := ec.PallasMina.G().Multiply(x)

	publicKey := Y.EncodeCompressed()
	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, x.Encode())
	copy(privateKey[len(privateKey)-PublicKeySize:], publicKey)

	return publicKey, privateKey
}

func Sign(privateKey []byte, input *SignInput) []byte {
	if len(privateKey) != PrivateKeySize {
		panic("minaschnorr: bad private key length" + strconv.Itoa(len(privateKey)))
	}

	return sign(privateKey[:32], input)
}

func SignRaw(rawPrivateKey []byte, input *SignInput) []byte {
	if len(rawPrivateKey) != 32 {
		panic("minaschnorr: bad raw private key length" + strconv.Itoa(len(rawPrivateKey)))
	}

	return sign(rawPrivateKey, input)
}

func sign(rawPrivateKey []byte, input *SignInput) []byte {
	privateKeyScalar, err := fq.DecodeScalar(rawPrivateKey)
	if err != nil || privateKeyScalar.Equals(fq.Zero()) {
		panic("minaschnorr: bad private key")
	}

	publicKey := ec.PallasMina.G().Multiply(privateKeyScalar)
	k := msgDerive(privateKeyScalar, input.Clone(), publicKey)
	if k.Equals(fq.Zero()) {
		panic("minaschnorr: k is zero")
	}

	// r = k*G
	r := ec.PallasMina.G().Multiply(k)
	rx, ry := pointCoordinates(r)
	if ry.Value().Bit(0) == 1 {
		k = k.Negate()
	}
	if rx.Equals(fp.Zero()) {
		panic("minaschnorr: rx is zero")
	}

	e, err := msgHash(publicKey, rx, input.Clone())
	if err != nil {
		panic("minaschnorr: hash failed" + err.Error())
	}

	// s = k + e*privateKey
	s := k.Add(e.Multiply(privateKeyScalar))
	if s.Equals(fq.Zero()) {
		panic("minaschnorr: s is zero")
	}

	rBytes := rx.Encode()
	ec.ReverseSlice(rBytes)
	sBytes := s.Encode()
	ec.ReverseSlice(sBytes)

	return append(rBytes, sBytes...)
}

func Verify(publicKey []byte, input *SignInput, signature []byte) bool {
	if len(publicKey) != PublicKeySize {
		panic("bad public key length" + strconv.Itoa(len(publicKey)))
	}

	if len(signature) != SignatureSize {
		return false
	}

	publicKeyPoint, err := ec.PallasMina.DecodePoint(publicKey, true)
	if err != nil {
		return false
	}
	if publicKeyPoint.IsPointAtInfinity() {
		return false
	}

	pointBuffer := make([]byte, 32)
	copy(pointBuffer, signature[:32])
	ec.ReverseSlice(pointBuffer)
	r, err := fp.DecodeScalar(pointBuffer)
	if err != nil {
		return false
	}
	if r.Equals(fp.Zero()) {
		return false
	}

	copy(pointBuffer, signature[32:])
	ec.ReverseSlice(pointBuffer)
	s, err := fq.DecodeScalar(pointBuffer)
	if err != nil {
		return false
	}
	if s.Equals(fq.Zero()) {
		return false
	}

	e, err := msgHash(publicKeyPoint, r, input.Clone())
	if err != nil {
		return false
	}
	sg := ec.PallasMina.G().MultiplyVarTime(s)

	epk := publicKeyPoint.MultiplyVarTime(e).Negate()

	R := sg.Add(epk)
	Rx, Ry := pointCoordinates(R)
	return Ry.Value().Bit(0) == 0 && Rx.Equals(r)
}

func Hash(input *SignInput) (ec.Scalar, error) {
	return poseidon.Hash(poseidon.NetworkType(input.networkID), input.FieldElements())
}

func msgHash(publicKey ec.Point, rx ec.Scalar, input *SignInput) (ec.Scalar, error) {
	x, y := pointCoordinates(publicKey)
	input.AddFp(x)
	input.AddFp(y)
	input.AddFp(rx)
	return Hash(input)
}

func msgDerive(privateKey ec.Scalar, input *SignInput, publicKey ec.Point) ec.Scalar {
	x, y := pointCoordinates(publicKey)
	input.AddFp(x)
	input.AddFp(y)
	input.AddFq(privateKey)
	input.AddBytes([]byte{byte(input.networkID)})
	inputBytes := input.Bytes()

	h, _ := blake2b.New(32, []byte{})
	_, _ = h.Write(inputBytes)
	hash := h.Sum(nil)

	// Clear the top two bits
	hash[31] &= 0x3F
	ec.ReverseSlice(hash)
	fe, err := fq.DecodeScalar(hash)
	if err != nil {
		// Since we clear the top two bits from hash, it will always be an element of Fq
		panic(fmt.Sprintf("error decoding hash as Fq element: %s", err))
	}
	return fe
}

func pointCoordinates(publicKey ec.Point) (ec.Scalar, ec.Scalar) {
	x, y, err := publicKey.Coordinates()
	if err != nil {
		panic(err)
	}
	return fp.NewScalarWithModularReduction(x), fp.NewScalarWithModularReduction(y)
}
