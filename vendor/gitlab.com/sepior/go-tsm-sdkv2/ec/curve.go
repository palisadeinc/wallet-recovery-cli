package ec

// Curve represents an elliptic curve. The point* methods implement the curve specific operations that are used by
// methods on a Point struct.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
	"sync"
)

const (
	curveSecp256k1  = 714
	curveP224       = 713
	curveP256       = 415
	curveP384       = 715
	curveP521       = 716
	curveEd25519    = 949
	curveEd448      = 960
	curveBLS12381E1 = 4000
	curveBLS12381E2 = 4001
)

var (
	Secp256k1    Curve
	P224         Curve
	P256         Curve
	P384         Curve
	P521         Curve
	Edwards25519 Curve
	Edwards448   Curve
	BLS12381E1   Curve
	BLS12381E2   Curve

	curvesInitialized sync.Once
	curves            = map[uint16]Curve{}
)

type Curve interface {
	Name() string
	Equals(o Curve) bool
	EncodedPointLength() int
	EncodedCompressedPointLength() int
	DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error)
	HashToPoint(message, domain []byte) (Point, error)
	NID() int
	G() Point
	O() Point
	Zn() Field
	Cofactor() *big.Int
	SupportsECDSA() bool
	SupportsSchnorr() bool
	PairingCurve() (PairingCurve, error)

	curveID() uint16
	pointEncode(p interface{}, compressed bool) []byte
	pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error)
	pointCoordinates(p interface{}) (*big.Int, *big.Int, error)
	pointAdd(p, q interface{}) interface{}
	pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{}
	pointMultiplyByCofactor(p interface{}) interface{}
	pointNegate(p interface{}) interface{}
	pointIsPointAtInfinity(p interface{}) bool
	pointIsInLargeSubgroup(p interface{}) bool
	pointEquals(p, q interface{}) bool
}

func init() {
	initCurves()
}

func initCurves() {
	curvesInitialized.Do(func() {
		Secp256k1 = newSWCurve(secp256k1.S256())
		curves[Secp256k1.curveID()] = Secp256k1

		P224 = newSWCurve(elliptic.P224())
		curves[P224.curveID()] = P224

		P256 = newSWCurve(elliptic.P256())
		curves[P256.curveID()] = P256

		P384 = newSWCurve(elliptic.P384())
		curves[P384.curveID()] = P384

		P521 = newSWCurve(elliptic.P521())
		curves[P521.curveID()] = P521

		P521 = newSWCurve(elliptic.P521())
		curves[P521.curveID()] = P521

		Edwards25519 = newEdwards25519()
		curves[Edwards25519.curveID()] = Edwards25519

		Edwards448 = newCurve448()
		curves[Edwards448.curveID()] = Edwards448

		BLS12381E1 = newBLS12381E1()
		curves[BLS12381E1.curveID()] = BLS12381E1

		BLS12381E2 = newBLS12381E2()
		curves[BLS12381E2.curveID()] = BLS12381E2
	})
}

func NewCurve(name string) (Curve, error) {
	for _, c := range curves {
		if c.Name() == name {
			return c, nil
		}
	}
	return nil, fmt.Errorf("unsupported curve: %s", name)
}

func CurveFromZn(zn Field) (Curve, error) {
	for _, c := range curves {
		if c.Zn().Equals(zn) {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no elliptic curve with a subgroup of order %s", zn.Modulus().String())
}

func newCurveFromID(id uint16) (Curve, error) {
	curve, exists := curves[id]
	if !exists {
		return nil, fmt.Errorf("no curve corresponds to ID: %d", id)
	}
	return curve, nil
}

func NewPointFromECPublicKey(publicKey *ecdsa.PublicKey) (Point, error) {
	curve, err := NewCurve(publicKey.Curve.Params().Name)
	if err != nil {
		return Point{}, err
	}

	pLen := (publicKey.Curve.Params().P.BitLen() + 7) / 8
	encodedPoint := make([]byte, 1+2*pLen)
	encodedPoint[0] = 4
	publicKey.X.FillBytes(encodedPoint[1 : 1+pLen])
	publicKey.Y.FillBytes(encodedPoint[1+pLen : 1+2*pLen])

	publicKeyPoint, err := curve.DecodePoint(encodedPoint, false)
	if err != nil {
		return Point{}, err
	}

	return publicKeyPoint, nil
}
