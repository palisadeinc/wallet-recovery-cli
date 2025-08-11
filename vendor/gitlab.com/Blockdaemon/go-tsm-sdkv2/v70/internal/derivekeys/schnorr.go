package derivekeys

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"github.com/gtank/merlin"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/schnorrvariant"
	"hash"
	"math/big"
)

func DeriveSchnorrKeys(schnorrVariant string, publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedKeys, error) {
	if err := validateSchnorrVariant(schnorrVariant, publicKey, privateKey); err != nil {
		return DerivedKeys{}, err
	}

	var err error
	switch schnorrVariant {
	case schnorrvariant.BIP340:
		publicKey, privateKey, chainCode, err = bip32KeyDerivation(publicKey, true, privateKey, chainCode, chainPath, cache)
	case schnorrvariant.ZilliqaSchnorr:
		publicKey, privateKey, chainCode, err = bip32KeyDerivation(publicKey, false, privateKey, chainCode, chainPath, cache)
	case schnorrvariant.Sr25519:
		publicKey, privateKey, chainCode, err = schnorrkelKeyDerivationUint32ChainPath(publicKey, privateKey, chainCode, chainPath, cache)
	default:
		publicKey, privateKey, chainCode, err = genericSchnorrKeyDerivation(publicKey, privateKey, chainCode, chainPath, cache)
	}
	if err != nil {
		return DerivedKeys{}, err
	}

	return DerivedKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}

func DeriveSchnorrPublicKey(schnorrVariant string, publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedPublicKey, error) {
	if err := validateSchnorrVariant(schnorrVariant, publicKey, publicKey.Curve().Zn().Zero()); err != nil {
		return DerivedPublicKey{}, err
	}

	var err error
	switch schnorrVariant {
	case schnorrvariant.BIP340:
		publicKey, _, chainCode, err = bip32KeyDerivation(publicKey, true, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
	case schnorrvariant.ZilliqaSchnorr:
		publicKey, _, chainCode, err = bip32KeyDerivation(publicKey, false, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
	case schnorrvariant.Sr25519:
		publicKey, _, chainCode, err = schnorrkelKeyDerivationUint32ChainPath(publicKey, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
	default:
		publicKey, _, chainCode, err = genericSchnorrKeyDerivation(publicKey, publicKey.Curve().Zn().Zero(), chainCode, chainPath, cache)
	}
	if err != nil {
		return DerivedPublicKey{}, err
	}

	return DerivedPublicKey{
		PublicKey: publicKey,
		ChainCode: chainCode,
	}, nil
}

func DeriveSchnorrPrivateKey(schnorrVariant string, privateKey ec.Scalar, publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Scalar, error) {
	if err := validateSchnorrVariant(schnorrVariant, publicKey, privateKey); err != nil {
		return ec.Scalar{}, err
	}

	var err error
	switch schnorrVariant {
	case schnorrvariant.BIP340:
		_, privateKey, _, err = bip32KeyDerivation(publicKey, true, privateKey, chainCode, chainPath, cache)
	case schnorrvariant.ZilliqaSchnorr:
		_, privateKey, _, err = bip32KeyDerivation(publicKey, false, privateKey, chainCode, chainPath, cache)
	case schnorrvariant.Sr25519:
		_, privateKey, _, err = schnorrkelKeyDerivationUint32ChainPath(publicKey, privateKey, chainCode, chainPath, cache)
	default:
		_, privateKey, _, err = genericSchnorrKeyDerivation(publicKey, privateKey, chainCode, chainPath, cache)
	}
	if err != nil {
		return ec.Scalar{}, err
	}

	return privateKey, nil
}

func genericSchnorrKeyDerivation(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Point, ec.Scalar, []byte, error) {
	if !publicKey.Curve().Equals(ec.Edwards25519) && !publicKey.Curve().Equals(ec.Edwards448) && !publicKey.Curve().Equals(ec.PallasMina) {
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

func schnorrkelKeyDerivationUint32ChainPath(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Point, ec.Scalar, []byte, error) {
	if !publicKey.Curve().Equals(ec.Ristretto255) {
		return ec.Point{}, ec.Scalar{}, nil, fmt.Errorf("unsupported elliptic curve for ristretto key derivation: %s", publicKey.Curve().Name())
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

	genericChainPath := make([][]byte, len(chainPath))
	for i, value := range chainPath {
		genericChainPath[i] = []byte(fmt.Sprintf("%d", value))
	}

	return schnorrkelKeyDerivation(publicKey, privateKey, chainCode, genericChainPath, cache)
}

func schnorrkelKeyDerivation(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath [][]byte, cache caching.Cache) (ec.Point, ec.Scalar, []byte, error) {
	encodedG := ec.Ristretto255.G().EncodeCompressed()
	for _, value := range chainPath {
		t := merlin.NewTranscript("SchnorrRistrettoHDKD")
		t.AppendMessage([]byte("sign-bytes"), value)

		t.AppendMessage([]byte("chain-code"), chainCode)
		t.AppendMessage([]byte("public-key"), publicKey.EncodeCompressed())

		scBytes := t.ExtractBytes([]byte("HDKD-scalar"), 64)

		ec.ReverseSlice(scBytes)
		sc := ec.Ristretto255.Zn().NewScalarWithModularReduction(new(big.Int).SetBytes(scBytes))

		privateKey = privateKey.Add(sc)

		gSC, err := pkMulX(ec.Ristretto255.G(), encodedG, sc, cache)
		if err != nil {
			return ec.Point{}, ec.Scalar{}, nil, err
		}
		publicKey = publicKey.Add(gSC)

		chainCode = t.ExtractBytes([]byte("HDKD-chaincode"), 32)
	}

	return publicKey, privateKey, chainCode, nil
}

func validateSchnorrVariant(schnorrVariant string, publicKey ec.Point, privateKey ec.Scalar) error {
	curve, err := schnorrvariant.VariantToCurve(schnorrVariant)
	if err != nil {
		return err
	}
	if !curve.Equals(publicKey.Curve()) {
		return fmt.Errorf("public key is not valid for schnorr variant: %s", schnorrVariant)
	}
	if !curve.Zn().Equals(privateKey.Field()) {
		return fmt.Errorf("private key is not valid for schnorr variant: %s", schnorrVariant)
	}
	return nil
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
	k := newCacheKey(encodedPK, x, pk.Curve())
	p, err := cache.GetOrSet(k, x, f)
	return p.(ec.Point), err
}

func newCacheKey(encodedPK []byte, x ec.Scalar, c ec.Curve) string {
	return fmt.Sprintf("kd_%s_%s_%d", c.Name(), base64.StdEncoding.EncodeToString(encodedPK), x.Value())
}
