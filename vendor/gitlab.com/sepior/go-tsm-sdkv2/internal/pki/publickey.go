package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/crypto/ed448"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	oidPublicKeyECDSA      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP224      = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384      = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521      = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidEd448   = asn1.ObjectIdentifier{1, 3, 101, 113}
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func MarshalPublicKey(publicKey crypto.PublicKey) ([]byte, error) {
	var algorithmIdentifier pkix.AlgorithmIdentifier
	var publicKeyBitString asn1.BitString

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		algorithmIdentifier.Algorithm = oidPublicKeyECDSA
		var paramBytes []byte
		oid, err := oidFromCurveName(publicKey.Params().Name)
		if err != nil {
			return nil, err
		}
		paramBytes, err = asn1.Marshal(oid)
		if err != nil {
			return nil, err
		}
		algorithmIdentifier.Parameters.FullBytes = paramBytes

		publicKeyBytes := elliptic.Marshal(publicKey.Curve, publicKey.X, publicKey.Y)
		publicKeyBitString = asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		}
	case ed25519.PublicKey:
		oid, err := oidFromCurveName("ED-25519")
		if err != nil {
			return nil, err
		}
		algorithmIdentifier.Algorithm = oid

		publicKeyBitString = asn1.BitString{
			Bytes:     publicKey,
			BitLength: 8 * len(publicKey),
		}
	case ed448.PublicKey:
		oid, err := oidFromCurveName("ED-448")
		if err != nil {
			return nil, err
		}
		algorithmIdentifier.Algorithm = oid

		publicKeyBitString = asn1.BitString{
			Bytes:     publicKey,
			BitLength: 8 * len(publicKey),
		}
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}

	spki := subjectPublicKeyInfo{
		Algorithm: algorithmIdentifier,
		PublicKey: publicKeyBitString,
	}

	return asn1.Marshal(spki)
}

func ParsePublicKey(derPublicKey []byte) (crypto.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(derPublicKey, &spki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after ASN.1 of public-key")
	}

	if spki.Algorithm.Algorithm.Equal(oidPublicKeyECDSA) {
		// ECDSA
		paramsData := spki.Algorithm.Parameters.FullBytes
		var namedCurveOID asn1.ObjectIdentifier
		rest, err := asn1.Unmarshal(paramsData, &namedCurveOID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ECDSA parameters as named curve")
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("trailing data after ECDSA parameters")
		}

		curve := namedCurveFromOID(namedCurveOID)
		if curve == nil {
			return nil, fmt.Errorf("unsupported elliptic curve")
		}

		asn1Data := spki.PublicKey.RightAlign()
		x, y := elliptic.Unmarshal(curve, asn1Data)
		if x == nil {
			return nil, fmt.Errorf("failed to unmarshal elliptic curve point")
		}
		pub := &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}
		return pub, nil
	} else if spki.Algorithm.Algorithm.Equal(oidEd25519) && len(spki.PublicKey.Bytes) == ed25519.PublicKeySize {
		// Ed25519
		return ed25519.PublicKey(spki.PublicKey.Bytes), nil
	} else if spki.Algorithm.Algorithm.Equal(oidEd448) && len(spki.PublicKey.Bytes) == ed448.PublicKeySize {
		// Ed448
		return ed448.PublicKey(spki.PublicKey.Bytes), nil
	}

	return nil, fmt.Errorf("unsupported public key type")
}

func ParseECDSAPublicKey(derPublicKey []byte) (*ecdsa.PublicKey, error) {
	publicKey, err := ParsePublicKey(derPublicKey)
	if err != nil {
		return nil, err
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an ECDSA public key")
	}

	return ecdsaPublicKey, nil
}

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveSecp256k1):
		return secp256k1.S256()
	}
	return nil
}

func oidFromCurveName(curveName string) (asn1.ObjectIdentifier, error) {
	switch curveName {
	case "secp256k1":
		return oidNamedCurveSecp256k1, nil
	case "P-224":
		return oidNamedCurveP224, nil
	case "P-256":
		return oidNamedCurveP256, nil
	case "P-384":
		return oidNamedCurveP384, nil
	case "P-521":
		return oidNamedCurveP521, nil
	case "ED-25519":
		return oidEd25519, nil
	case "ED-448":
		return oidEd448, nil
	}
	return asn1.ObjectIdentifier{}, fmt.Errorf("unsupported elliptic curve")
}
