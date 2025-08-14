package sr25519

import (
	"bytes"
	"crypto"
	"crypto/sha512"
	"github.com/gtank/merlin"
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
	SeedSize       = 32
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
	copy(publicKey, privateKey[SeedSize:])

	return publicKey, privateKey, nil
}

func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("sr25519: bad seed length: " + strconv.Itoa(l))
	}

	sk, _ := expandSeed(seed)
	publicKey := ec.Ristretto255.G().Multiply(sk)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, seed)
	copy(privateKey[32:], publicKey.EncodeCompressed())
	return privateKey
}

func expandSeed(seed []byte) (ec.Scalar, []byte) {
	h := sha512.Sum512(seed)
	key := h[:32]
	nonce := h[32:]

	key[0] &= 248
	key[31] &= 63
	key[31] |= 64
	ec.ReverseSlice(key)

	s := new(big.Int).SetBytes(key)
	// Divide by Edwards2519 co-factor
	s.Rsh(s, 3)

	return ec.Ristretto255.Zn().NewScalarWithModularReduction(s), nonce
}

func signingContext(context, message []byte) *merlin.Transcript {
	t := merlin.NewTranscript("SigningContext")
	t.AppendMessage([]byte(""), context)
	t.AppendMessage([]byte("sign-bytes"), message)
	return t
}

func Sign(privateKey, context, message []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("sr25519: bad private key length: " + strconv.Itoa(l))
	}

	x, _ := expandSeed(privateKey[:32])

	return sign(x, privateKey[32:], context, message, ec.Ristretto255.Zn().NewRandomScalar())
}

func SignRaw(rawPrivateKey, publicKey, context, message []byte) []byte {
	if l := len(rawPrivateKey); l != 32 {
		panic("sr25519: bad raw private key length: " + strconv.Itoa(l))
	}

	x, err := ec.Ristretto255.Zn().DecodeScalar(rawPrivateKey)
	if err != nil {
		panic("sr25519: bad raw private key: " + err.Error())
	}

	return sign(x, publicKey, context, message, ec.Ristretto255.Zn().NewRandomScalar())
}

func sign(x ec.Scalar, publicKey, context, message []byte, r ec.Scalar) []byte {
	t := signingContext(context, message)
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	t.AppendMessage([]byte("sign:pk"), publicKey)

	R := ec.Ristretto255.G().Multiply(r)
	t.AppendMessage([]byte("sign:R"), R.EncodeCompressed())

	kb := t.ExtractBytes([]byte("sign:c"), 64)
	ec.ReverseSlice(kb)
	k := ec.Ristretto255.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(kb))

	s := r.Add(k.Multiply(x))

	signature := make([]byte, SignatureSize)
	copy(signature[:32], R.EncodeCompressed())
	copy(signature[32:], s.Encode())
	ec.ReverseSlice(signature[32:])
	signature[63] |= 128

	return signature
}

func Verify(publicKey, context, message, signature []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("sr25519: bad public key length: " + strconv.Itoa(l))
	}

	if len(signature) != SignatureSize {
		return false
	}
	if signature[63]&128 == 0 {
		return false
	}

	publicKeyPoint, err := ec.Ristretto255.DecodePoint(publicKey, true)
	if err != nil {
		return false
	}
	if publicKeyPoint.IsPointAtInfinity() {
		return false
	}

	sigCopy := make([]byte, SignatureSize)
	copy(sigCopy, signature)
	sigCopy[63] &= 127

	R, err := ec.Ristretto255.DecodePoint(sigCopy[:32], true)
	if err != nil {
		return false
	}
	if R.IsPointAtInfinity() {
		return false
	}

	ec.ReverseSlice(sigCopy[32:])
	s, err := ec.Ristretto255.Zn().DecodeScalar(sigCopy[32:])
	if err != nil {
		return false
	}
	if s.Equals(ec.Ristretto255.Zn().Zero()) {
		return false
	}

	t := signingContext(context, message)
	t.AppendMessage([]byte("proto-name"), []byte("Schnorr-sig"))
	t.AppendMessage([]byte("sign:pk"), publicKey)
	t.AppendMessage([]byte("sign:R"), sigCopy[:32])

	kb := t.ExtractBytes([]byte("sign:c"), 64)
	ec.ReverseSlice(kb)
	k := ec.Ristretto255.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(kb))
	if k.Equals(ec.Ristretto255.Zn().Zero()) {
		return false
	}

	// Check s*G - k*PublicKey == R
	return ec.Ristretto255.G().MultiplyVarTime(s).Subtract(publicKeyPoint.MultiplyVarTime(k)).Equals(R)
}
