package derivekeys

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ec"
	"hash"
	"math/big"
)

func DeriveSchnorrKeys(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedKeys, error) {
	if !publicKey.Curve().SupportsSchnorr() {
		return DerivedKeys{}, fmt.Errorf("unsupported elliptic curve for schnorr key derivation: %s", publicKey.Curve().Name())
	}

	if publicKey.Curve().Equals(ec.Secp256k1) {
		var err error
		publicKey, privateKey, chainCode, err = bip32KeyDerivation(publicKey, true, privateKey, chainCode, chainPath, cache)
		if err != nil {
			return DerivedKeys{}, err
		}
	} else {
		var err error
		publicKey, privateKey, chainCode, err = v1SchnorrKeyDerivation(publicKey, privateKey, chainCode, chainPath, cache)
		if err != nil {
			return DerivedKeys{}, err
		}
	}

	return DerivedKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}

func DeriveSchnorrPublicKey(publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedPublicKey, error) {
	if !publicKey.Curve().SupportsSchnorr() {
		return DerivedPublicKey{}, fmt.Errorf("unsupported elliptic curve for schnorr key derivation: %s", publicKey.Curve().Name())
	}

	if publicKey.Curve().Equals(ec.Secp256k1) {
		var err error
		publicKey, _, chainCode, err = bip32KeyDerivation(publicKey, true, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
		if err != nil {
			return DerivedPublicKey{}, err
		}
	} else {
		var err error
		publicKey, _, chainCode, err = v1SchnorrKeyDerivation(publicKey, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
		if err != nil {
			return DerivedPublicKey{}, err
		}
	}

	return DerivedPublicKey{
		PublicKey: publicKey,
		ChainCode: chainCode,
	}, nil
}

func DeriveSchnorrPrivateKey(privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Scalar, error) {
	curve, err := ec.CurveFromZn(privateKey.Field())
	if err != nil {
		return ec.Scalar{}, err
	}
	if !curve.SupportsSchnorr() {
		return ec.Scalar{}, fmt.Errorf("unsupported elliptic curve for schnorr key derivation: %s", curve.Name())
	}

	if curve.Equals(ec.Secp256k1) {
		publicKey := curve.G().Multiply(privateKey)
		_, privateKey, _, err = bip32KeyDerivation(publicKey, true, privateKey, chainCode, chainPath, cache)
		return privateKey, err
	} else {
		publicKey := curve.G().Multiply(privateKey)
		_, privateKey, _, err = v1SchnorrKeyDerivation(publicKey, privateKey, chainCode, chainPath, cache)
		return privateKey, err
	}
}

func v1SchnorrKeyDerivation(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Point, ec.Scalar, []byte, error) {
	if !publicKey.Curve().Equals(ec.Edwards25519) && !publicKey.Curve().Equals(ec.Edwards448) {
		return ec.Point{}, ec.Scalar{}, nil, fmt.Errorf("unsupported elliptic curve for V1 key derivation: %s", publicKey.Curve().Name())
	}

	if len(chainPath) == 0 {
		return publicKey, privateKey, chainCode, nil
	}
	if len(chainPath) > maxChainPathDepth {
		return ec.Point{}, ec.Scalar{}, nil, fmt.Errorf("max depth %d exceeded: %d", maxChainPathDepth, len(chainPath))
	}
	for _, value := range chainPath {
		if value&0x80000000 != 0 {
			return ec.Point{}, ec.Scalar{}, nil, fmt.Errorf("hardened keys are not supported")
		}
	}

	hashLength := publicKey.Curve().Zn().ByteLen()
	if hashLength > 64 {
		hashLength = 64
	}

	var h func() hash.Hash
	if hashLength == 32 {
		h = sha256.New
	} else {
		h = sha512.New
	}

	encodedValue := make([]byte, 4)
	for _, value := range chainPath {
		encodedPublicKey := publicKey.Encode()
		binary.LittleEndian.PutUint32(encodedValue, value)

		keyOffsetDigest := hMAC(h, chainCode, []byte{0x02}, encodedPublicKey, encodedValue)
		keyIdOffset := publicKey.Curve().Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(keyOffsetDigest))

		var err error
		publicKey, err = pkMulX(publicKey, encodedPublicKey, keyIdOffset, cache)
		if err != nil {
			return ec.Point{}, ec.Scalar{}, nil, err
		}
		privateKey = privateKey.Multiply(keyIdOffset)
		chainCode = hMAC(h, chainCode, []byte{0x03}, encodedPublicKey, encodedValue)[0:hashLength]
	}

	return publicKey, privateKey, chainCode, nil
}

func hMAC(h func() hash.Hash, k []byte, data ...[]byte) []byte {
	hasher := hmac.New(h, k)
	for _, buf := range data {
		hasher.Write(buf)
	}
	return hasher.Sum(nil)
}

func pkMulX(pk ec.Point, encodedPK []byte, x ec.Scalar, cache caching.Cache) (ec.Point, error) {
	f := func(key interface{}, data interface{}) (interface{}, error) {
		return pk.Multiply(x), nil
	}
	k := newV1CacheKey(encodedPK, x, pk.Curve())
	p, err := cache.GetOrSet(k, x, f)
	return p.(ec.Point), err
}

func newV1CacheKey(encodedPK []byte, x ec.Scalar, c ec.Curve) string {
	return fmt.Sprintf("v1_%s_%s_%d", c.Name(), base64.StdEncoding.EncodeToString(encodedPK), x.Value())
}
