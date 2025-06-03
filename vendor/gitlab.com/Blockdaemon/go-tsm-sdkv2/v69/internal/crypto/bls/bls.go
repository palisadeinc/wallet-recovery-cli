package bls

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/random"
	"golang.org/x/crypto/hkdf"
	"io"
	"math/big"
	"strconv"
)

const (
	ShortPublicKeySize  = 48
	ShortPrivateKeySize = 32 + ShortPublicKeySize
	LongPublicKeySize   = 96
	LongPrivateKeySize  = 32 + LongPublicKeySize
	ShortSignatureSize  = 48
	LongSignatureSize   = 96
	SeedSize            = 32
)

type SignatureVariant int

const (
	MinimalSignatureSize SignatureVariant = iota + 1
	MinimalPubKeySize
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
	publicKey := make([]byte, len(priv[32:]))
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(priv, xx)
}

func GenerateKey(rand io.Reader, signatureVariant SignatureVariant) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = random.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privKey := NewKeyFromSeed(seed, signatureVariant)
	pubKey := make([]byte, len(privKey[32:]))
	copy(pubKey, privKey[32:])

	return pubKey, privKey, nil
}

func NewKeyFromSeed(seed []byte, signatureVariant SignatureVariant) PrivateKey {
	_, _, _, pubKeySize, _ := params(signatureVariant)
	privKey := make([]byte, 32+pubKeySize)
	newKeyFromSeed(privKey, seed, []byte("BLS-SIG-KEYGEN-SALT-"), signatureVariant)
	return privKey
}

func newKeyFromSeed(privKey, seed, salt []byte, signatureVariant SignatureVariant) {
	_, pubKeyCurve, _, _, _ := params(signatureVariant)

	if l := len(seed); l < SeedSize {
		panic("bls: bad seed length: " + strconv.Itoa(l))
	}

	// IKM || I2OSP(0, 1)
	ikm := make([]byte, len(seed)+1)
	copy(ikm, seed)

	// key_info || I2OSP(L, 2), L = 48
	info := []byte{0, 48}

	var privateKey ec.Scalar
	for {
		// PRK = HKDF-Extract(salt, IKM || I2OSP(0, 1))
		prk := hkdf.Extract(sha256.New, ikm, salt)

		// OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)
		okmReader := hkdf.Expand(sha256.New, prk, info)
		okm := make([]byte, 48)
		_, _ = io.ReadFull(okmReader, okm)

		// SK = OS2IP(OKM) mod r
		var sk big.Int
		sk.SetBytes(okm)
		privateKey = pubKeyCurve.Zn().NewScalarWithModularReduction(&sk)

		// if SK != 0: return SK
		if !privateKey.Equals(privateKey.Field().Zero()) {
			break
		}

		// salt = H(salt)
		h := sha256.New()
		h.Write(salt)
		salt = h.Sum(nil)
	}

	pubKey := pubKeyCurve.G().Multiply(privateKey)
	copy(privKey, privateKey.Encode())
	copy(privKey[32:], pubKey.EncodeCompressed())
}

func Sign(privateKey PrivateKey, message []byte) []byte {
	signatureVariant, err := pubKeyToSignatureVariant(privateKey[32:])
	if err != nil {
		panic("bls: " + err.Error())
	}
	_, _, sigSize, _, _ := params(signatureVariant)
	signature := make([]byte, sigSize)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	signatureVariant, err := pubKeyToSignatureVariant(privateKey[32:])
	if err != nil {
		panic("bls: " + err.Error())
	}
	sigCurve, pubKeyCurve, _, _, domain := params(signatureVariant)

	privKey, err := pubKeyCurve.Zn().DecodeScalar(privateKey[:32])
	if err != nil {
		panic("bls: bad private key: " + err.Error())
	}

	mh, err := sigCurve.HashToPoint(message, []byte(domain))
	if err != nil {
		panic("bls: hash to point error: " + err.Error())
	}

	sigma := mh.Multiply(privKey)
	copy(signature, sigma.EncodeCompressed())
}

func Verify(publicKey, message, sig []byte) bool {
	signatureVariant, err := pubKeyToSignatureVariant(publicKey)
	if err != nil {
		panic("bls: " + err.Error())
	}
	sigCurve, pubKeyCurve, sigSize, _, domain := params(signatureVariant)

	if len(sig) != sigSize {
		return false
	}

	// R = signature_to_point(signature)
	// If R is INVALID, return INVALID
	// If signature_subgroup_check(R) is INVALID, return INVALID
	R, err := sigCurve.DecodePoint(sig, true)
	if err != nil {
		return false
	}

	// If KeyValidate(PK) is INVALID, return INVALID
	// xP = pubkey_to_point(PK)
	xP, err := pubKeyCurve.DecodePoint(publicKey, true)
	if err != nil {
		return false
	}
	if xP.IsPointAtInfinity() {
		return false
	}

	// Q = hash_to_point(message)
	Q, err := sigCurve.HashToPoint(message, []byte(domain))
	if err != nil {
		return false
	}

	var C1, C2 ec.Element
	if signatureVariant == MinimalSignatureSize {
		// C1 = pairing(Q, xP)
		C1, err = ec.BLS12381.Pair(Q, xP)
		if err != nil {
			return false
		}
		// C2 = pairing(R, P)
		C2, err = ec.BLS12381.Pair(R, pubKeyCurve.G())
		if err != nil {
			return false
		}
	} else {
		// C1 = pairing(xP, Q)
		C1, err = ec.BLS12381.Pair(xP, Q)
		if err != nil {
			return false
		}
		// C2 = pairing(P, R)
		C2, err = ec.BLS12381.Pair(pubKeyCurve.G(), R)
		if err != nil {
			return false
		}
	}

	// If C1 == C2, return VALID, else return INVALID
	return C2.Equals(C1)
}

func params(signatureVariant SignatureVariant) (sigCurve, pubKeyCurve ec.Curve, sigSize, pubKeySize int, domain string) {
	if signatureVariant == MinimalSignatureSize {
		return ec.BLS12381E1, ec.BLS12381E2, ShortSignatureSize, LongPublicKeySize, "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	} else if signatureVariant == MinimalPubKeySize {
		return ec.BLS12381E2, ec.BLS12381E1, LongSignatureSize, ShortPublicKeySize, "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
	} else {
		panic("bls: bad signature variant")
	}
}

func pubKeyToSignatureVariant(pubKey []byte) (SignatureVariant, error) {
	if len(pubKey) == LongPublicKeySize {
		return MinimalSignatureSize, nil
	} else if len(pubKey) == ShortPublicKeySize {
		return MinimalPubKeySize, nil
	} else {
		return 0, fmt.Errorf("bad key length: " + strconv.Itoa(len(pubKey)))
	}
}
