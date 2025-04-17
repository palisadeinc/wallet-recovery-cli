package ers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"github.com/palisadeinc/mpc-recovery/math"
)

// DeriveEd25519 derives multiplicatively.
func DeriveEd25519(masterPublicKey math.Point, masterPrivateKey math.Scalar, masterChainCode []byte, chainPath []uint32) (derivedPublicKey math.Point, derivedPrivateKey math.Scalar, derivedChainCode []byte, err error) {

	encodedValue := make([]byte, 4)
	chainCode := masterChainCode
	publicKey := masterPublicKey
	privateKey := masterPrivateKey

	for _, value := range chainPath {
		if value&0x80000000 != 0 {
			return math.Point{}, math.Scalar{}, nil, errors.New("hardened derivation is not supported")
		}
		encodedPublicKey := publicKey.Encode()
		binary.LittleEndian.PutUint32(encodedValue, value)
		keyOffsetDigest := HMAC(sha256.New, chainCode, []byte{0x02}, encodedPublicKey, encodedValue)
		keyIdOffset := publicKey.Curve().NewScalarBytes(keyOffsetDigest)
		publicKey = publicKey.Mul(keyIdOffset)
		privateKey = privateKey.Mul(keyIdOffset)
		chainCode = HMAC(sha256.New, chainCode, []byte{0x03}, encodedPublicKey, encodedValue)
	}

	return publicKey, privateKey, chainCode, nil
}

// DeriveSecp256k1 derives additively according to the BIP-32 standard.
// See https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
func DeriveSecp256k1(masterPublicKey math.Point, masterPrivateKey math.Scalar, masterChainCode []byte, chainPath []uint32) (derivedPublicKey math.Point, derivedPrivateKey math.Scalar, derivedChainCode []byte, err error) {

	chainCode := masterChainCode
	publicKey := masterPublicKey
	privateKey := masterPrivateKey

	for _, value := range chainPath {

		if value&0x80000000 != 0 {
			return math.Point{}, math.Scalar{}, nil, errors.New("hardened derivation is not supported")
		}

		w := bytes.Buffer{}
		b := encodePointBIP32(publicKey)
		_, _ = w.Write(b)

		err = binary.Write(&w, binary.BigEndian, value)
		if err != nil {
			return math.Point{}, math.Scalar{}, nil, err
		}
		allBytes := HMAC(sha512.New, chainCode, w.Bytes())
		leftBytes := allBytes[:32]
		rightBytes := allBytes[32:]
		offset := publicKey.Curve().NewScalarBytes(leftBytes)

		privateKey = privateKey.Add(offset)

		mG := publicKey.Curve().G().Mul(offset)
		publicKey = publicKey.Add(mG)

		chainCode = rightBytes
	}

	return publicKey, privateKey, chainCode, nil
}

func HMAC(h func() hash.Hash, k []byte, data ...[]byte) []byte {
	hasher := hmac.New(h, k)
	for _, buf := range data {
		hasher.Write(buf)
	}
	return hasher.Sum(nil)
}

// EncodePoint is the "ser_P(P)" from the BIP-32 standard.
func encodePointBIP32(p math.Point) []byte {
	var pBuf = &bytes.Buffer{}
	X, Y := p.Coordinates()

	if Y.Bit(0) == 0 {
		_ = pBuf.WriteByte(0x02)
	} else {
		_ = pBuf.WriteByte(0x03)
	}
	for i := len(X.Bytes()); i < 32; i++ {
		_ = pBuf.WriteByte(0x0)
	}
	_, _ = pBuf.Write(X.Bytes())
	return pBuf.Bytes()
}
