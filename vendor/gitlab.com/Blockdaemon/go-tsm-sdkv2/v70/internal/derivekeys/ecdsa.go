package derivekeys

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
)

const maxChainPathDepth = 50

type DerivedKeys struct {
	PrivateKey ec.Scalar
	PublicKey  ec.Point
	ChainCode  []byte
}

type DerivedPublicKey struct {
	PublicKey ec.Point
	ChainCode []byte
}

func DeriveECDSAKeys(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedKeys, error) {
	var err error
	publicKey, privateKey, chainCode, err = bip32KeyDerivation(publicKey, false, privateKey, chainCode, chainPath, cache)
	if err != nil {
		return DerivedKeys{}, err
	}

	return DerivedKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}

func DeriveECDSAPublicKey(publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedPublicKey, error) {
	var err error
	publicKey, _, chainCode, err = bip32KeyDerivation(publicKey, false, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
	if err != nil {
		return DerivedPublicKey{}, err
	}

	return DerivedPublicKey{
		PublicKey: publicKey,
		ChainCode: chainCode,
	}, nil
}

func DeriveECDSAPrivateKey(privateKey ec.Scalar, publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Scalar, error) {
	_, privateKey, _, err := bip32KeyDerivation(publicKey, false, privateKey, chainCode, chainPath, cache)
	return privateKey, err
}

func bip32KeyDerivation(publicKey ec.Point, xOnlyPublicKey bool, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Point, ec.Scalar, []byte, error) {
	if !publicKey.Curve().Equals(ec.Secp256k1) {
		return ec.Point{}, ec.Scalar{}, nil, fmt.Errorf("unsupported elliptic curve for BIP-32 key derivation: %s", publicKey.Curve().Name())
	}

	if xOnlyPublicKey {
		publicKey, privateKey = correctXOnlyKeys(publicKey, privateKey)
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

	encodedValue := make([]byte, 4)
	for _, value := range chainPath {
		encodedPublicKey := publicKey.EncodeCompressed()
		binary.BigEndian.PutUint32(encodedValue, value)

		lr := hMAC(sha512.New, chainCode, encodedPublicKey, encodedValue)
		m, err := publicKey.Curve().Zn().DecodeScalar(lr[:32])
		if err != nil {
			return ec.Point{}, ec.Scalar{}, nil, err
		}
		gM, err := gMulX(publicKey.Curve(), m, cache)
		if err != nil {
			return ec.Point{}, ec.Scalar{}, nil, err
		}
		publicKey = gM.Add(publicKey)
		privateKey = privateKey.Add(m)
		if xOnlyPublicKey {
			publicKey, privateKey = correctXOnlyKeys(publicKey, privateKey)
		}
		chainCode = lr[32:]
	}

	return publicKey, privateKey, chainCode, nil
}

func correctXOnlyKeys(publicKey ec.Point, privateKey ec.Scalar) (ec.Point, ec.Scalar) {
	_, y, err := publicKey.Coordinates()
	if err != nil {
		panic(err)
	}
	if y.Bit(0) == 1 {
		return publicKey.Negate(), privateKey.Negate()
	}
	return publicKey, privateKey
}

func gMulX(curve ec.Curve, x ec.Scalar, cache caching.Cache) (ec.Point, error) {
	f := func(key interface{}, data interface{}) (interface{}, error) {
		return curve.G().Multiply(x), nil
	}
	k := newBIP32CacheKey(x, curve)
	p, err := cache.GetOrSet(k, x, f)
	return p.(ec.Point), err
}

func newBIP32CacheKey(x ec.Scalar, c ec.Curve) string {
	return fmt.Sprintf("bip32_%s_%d", c.Name(), x.Value())
}
