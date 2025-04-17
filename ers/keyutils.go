package ers

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/palisadeinc/mpc-recovery/math"
)

var (
	oidPublicKeyECDSA      = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidNamedCurveP224      = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256      = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384      = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521      = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

	oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}
)

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func ParsePublicKey(derPublicKey []byte) (crypto.PublicKey, error) {
	var spki subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(derPublicKey, &spki); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, fmt.Errorf("trailing data after ASN.1 of public key")
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
	} else if spki.Algorithm.Algorithm.Equal(oidEd25519) {
		// Ed25519
		return ed25519.PublicKey(spki.PublicKey.Bytes), nil
	}

	return nil, fmt.Errorf("unsupported public key type")
}

func marshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	oid, ok := oidFromNamedCurve(key.Curve)
	if !ok {
		return nil, fmt.Errorf("unsupported elliptic curve")
	}

	privateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    key.D.FillBytes(privateKey),
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	case math.S256():
		return oidNamedCurveSecp256k1, true
	}

	return nil, false
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
		return math.S256()
	}
	return nil
}

func getPublicKeyFromBytes(expectedCurve math.Curve, publicKeyBytes []byte) (publicKey math.Point, err error) {

	switch expectedCurve.Name() {
	case "secp256k1", "P-224", "P-256", "P-384", "P-521":
		publicKey, err := ParsePublicKey(publicKeyBytes)
		if err != nil {
			return math.Point{}, fmt.Errorf("invalid public key: %w", err)
		}

		switch publicKey := publicKey.(type) {
		case *ecdsa.PublicKey:
			if publicKey.Curve.Params().Name != expectedCurve.Name() {
				return math.Point{}, fmt.Errorf("mismatch between curve types of recovery data (%s) and provided public key (%s)", publicKey.Curve.Params().Name, expectedCurve.Name())
			}
			curve, err := math.NewCurve(publicKey.Curve.Params().Name)
			if err != nil {
				return math.Point{}, err
			}
			return curve.NewPoint(publicKey.X, publicKey.Y)
		default:
			return math.Point{}, fmt.Errorf("curve mismatch: recovery data wants %s, but was %v", expectedCurve.Name(), publicKey)
		}

	case "ED-25519", "ED-448":
		publicKey, err = expectedCurve.DecodePoint(publicKeyBytes)
		if err != nil {
			return math.Point{}, fmt.Errorf("invalid public key: %w", err)
		}

	default:
		return math.Point{}, fmt.Errorf("unsupported curve: %s", expectedCurve.Name())
	}
	return publicKey, nil
}
