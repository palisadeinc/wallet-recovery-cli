package bip340

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"io"
	"math/big"
	"strconv"
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

	x := ec.Secp256k1.Zn().NewScalarFromReader(rand)
	Y := ec.Secp256k1.G().Multiply(x)
	publicKey := make([]byte, PublicKeySize)
	pkX, _, err := Y.Coordinates()
	if err != nil {
		panic(err)
	}
	pkX.FillBytes(publicKey)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, x.Encode())
	copy(privateKey[len(privateKey)-PublicKeySize:], publicKey)

	return publicKey, privateKey
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("bip340: bad private key length: " + strconv.Itoa(l))
	}

	return sign(privateKey[:32], privateKey[32:], message, random.Bytes(32))
}

func SignRaw(rawPrivateKey, publicKey, message []byte) []byte {
	if l := len(rawPrivateKey); l != 32 {
		panic("bip340: bad private key length: " + strconv.Itoa(l))
	}

	return sign(rawPrivateKey, publicKey, message, random.Bytes(32))
}

func sign(rawPrivateKey, publicKey, message, auxRand []byte) []byte {
	// Let d' = int(sk)

	dPrime, err := ec.Secp256k1.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		panic("bip340: bad private key: " + err.Error())
	}

	// Fail if d' = 0 or d' ≥ n

	if dPrime.Equals(ec.Secp256k1.Zn().Zero()) {
		panic("bip340: private key is zero")
	}

	// Let P = d'⋅G

	P := ec.Secp256k1.G().Multiply(dPrime)

	// Let d = d' if has_even_y(P), otherwise let d = n - d'

	x, y, err := P.Coordinates()
	if err != nil {
		panic(err)
	}
	var d ec.Scalar
	if y.Bit(0) == 1 {
		d = dPrime.Negate()
	} else {
		d = dPrime
	}

	// Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a).

	t := hash("BIP0340/aux", auxRand)
	subtle.XORBytes(t, d.Encode(), t)

	// Let rand = hashBIP0340/nonce(t || bytes(P) || m).

	bytesP := make([]byte, PublicKeySize)
	x.FillBytes(bytesP)
	rand := hash("BIP0340/nonce", t, bytesP, message)

	// Let k' = int(rand) mod n.

	kPrime, err := ec.Secp256k1.Zn().DecodeScalar(rand)
	if err != nil {
		panic("bip340: nonce value: " + err.Error())
	}

	// Fail if k' = 0.

	if kPrime.Equals(ec.Secp256k1.Zn().Zero()) {
		panic("bip340: nonce is zero")
	}

	// Let R = k'⋅G.

	R := ec.Secp256k1.G().Multiply(kPrime)

	// Let k = k' if has_even_y(R), otherwise let k = n - k' .

	x, y, err = R.Coordinates()
	if err != nil {
		panic(err)
	}
	var k ec.Scalar
	if y.Bit(0) == 1 {
		k = kPrime.Negate()
	} else {
		k = kPrime
	}

	// Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.

	bytesR := make([]byte, PublicKeySize)
	x.FillBytes(bytesR)
	e := hash("BIP0340/challenge", bytesR, bytesP, message)

	// Let sig = bytes(R) || bytes((k + ed) mod n).

	ePrime, err := ec.Secp256k1.Zn().DecodeScalar(e)
	if err != nil {
		panic("bip340: bad challenge value: " + err.Error())
	}
	s := k.Add(ePrime.Multiply(d))

	signature := make([]byte, SignatureSize)
	copy(signature, bytesR)
	copy(signature[len(bytesR):], s.Encode())

	// If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].

	if !Verify(publicKey, message, signature) {
		panic("bip340: signature verification failed")
	}

	return signature
}

func Verify(publicKey, message, sig []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("bip340: bad public key length: " + strconv.Itoa(l))
	}

	if len(sig) != SignatureSize {
		return false
	}

	// Let P = lift_x(int(pk)); fail if that fails.

	P, err := liftX(publicKey)
	if err != nil {
		return false
	}

	// Let r = int(sig[0:32]); fail if r ≥ p.

	r := new(big.Int).SetBytes(sig[0:32])
	if r.Cmp(secp256k1FpModulus) >= 0 {
		return false
	}

	// Let s = int(sig[32:64]); fail if s ≥ n.

	s, err := ec.Secp256k1.Zn().DecodeScalar(sig[32:64])
	if err != nil {
		return false
	}

	// Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.

	e := hash("BIP0340/challenge", sig[0:32], publicKey, message)

	// Let R = s⋅G - e⋅P.

	ePrime, err := ec.Secp256k1.Zn().DecodeScalar(e)
	if err != nil {
		panic("bip340: bad challenge value: " + err.Error())
	}
	R := ec.Secp256k1.G().MultiplyVarTime(s).Subtract(P.MultiplyVarTime(ePrime))

	// Fail if is_infinite(R).

	if R.IsPointAtInfinity() {
		return false
	}

	// Fail if not has_even_y(R).

	x, y, err := R.Coordinates()
	if err != nil {
		panic(err)
	}
	if y.Bit(0) == 1 {
		return false
	}

	// Fail if x(R) ≠ r.

	if x.Cmp(r) != 0 {
		return false
	}

	return true
}

func hash(name string, values ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(name))
	tagHash := h.Sum(nil)

	h.Reset()
	h.Write(tagHash)
	h.Write(tagHash)
	for _, v := range values {
		h.Write(v)
	}

	return h.Sum(nil)
}

var secp256k1FpModulus, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
var secp256k1FpModulusAddOneDivFour, _ = new(big.Int).SetString("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFFFFF0C", 16)

func liftX(v []byte) (ec.Point, error) {
	x := new(big.Int).SetBytes(v)
	if x.Cmp(secp256k1FpModulus) >= 1 {
		return ec.Point{}, fmt.Errorf("bip340: x value out of range")
	}

	c := new(big.Int).Exp(x, big.NewInt(3), secp256k1FpModulus)
	c.Add(c, big.NewInt(7))
	c.Mod(c, secp256k1FpModulus)
	y := new(big.Int).Exp(c, secp256k1FpModulusAddOneDivFour, secp256k1FpModulus)

	y2 := new(big.Int).Exp(y, big.NewInt(2), secp256k1FpModulus)
	if c.Cmp(y2) != 0 {
		return ec.Point{}, fmt.Errorf("bip340: c != y^2")
	}

	if y.Bit(0) == 0 {
		return point(x, y)
	} else {
		return point(x, y.Sub(secp256k1FpModulus, y))
	}
}

func point(x, y *big.Int) (ec.Point, error) {
	pBytes := make([]byte, 65)
	pBytes[0] = 4
	x.FillBytes(pBytes[1:33])
	y.FillBytes(pBytes[33:65])
	R, err := ec.Secp256k1.DecodePoint(pBytes, true)
	if err != nil {
		return ec.Point{}, fmt.Errorf("bip340: invalid point: %s", err)
	}
	return R, nil
}
