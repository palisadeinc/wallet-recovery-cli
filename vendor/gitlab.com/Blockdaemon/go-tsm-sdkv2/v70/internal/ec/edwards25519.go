package ec

import (
	"fmt"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"
)

var (
	edwards25519ScOne      *edwards25519.Scalar
	edwards25519ScMinusOne *edwards25519.Scalar
)

type edwards25519CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type edwards25519Curve struct {
	params *edwards25519CurveParams
}

func newEdwards25519() Curve {
	initFields()

	params := &edwards25519CurveParams{
		name: "ED-25519",
	}

	curve := edwards25519Curve{
		params: params,
	}

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value:     edwards25519.NewGeneratorPoint(),
	}

	params.o = Point{
		curve: curve,
		value: edwards25519.NewIdentityPoint(),
	}

	params.zn = fields[fieldEdwards25519Zn]

	edwards25519ScOne, _ = edwards25519.NewScalar().SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	edwards25519ScMinusOne, _ = edwards25519.NewScalar().SetCanonicalBytes([]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16})

	params.cofactor = big.NewInt(8)

	return curve
}

func toEdwards25519Point(p interface{}) *edwards25519.Point {
	pp, valid := p.(*edwards25519.Point)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (c edwards25519Curve) Name() string {
	return c.params.name
}

func (c edwards25519Curve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c edwards25519Curve) EncodedPointLength() int {
	return 32
}

func (c edwards25519Curve) EncodedCompressedPointLength() int {
	return 32
}

func (c edwards25519Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c edwards25519Curve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", c.Name())
}

func (c edwards25519Curve) NID() int {
	return 0
}

func (c edwards25519Curve) G() Point {
	return c.params.g
}

func (c edwards25519Curve) O() Point {
	return c.params.o
}

func (c edwards25519Curve) Zn() Field {
	return c.params.zn
}

func (c edwards25519Curve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c edwards25519Curve) SupportsECDSA() bool {
	return false
}

func (c edwards25519Curve) SupportsSchnorr() bool {
	return true
}

func (c edwards25519Curve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", c.params.name)
}

func (c edwards25519Curve) curveID() uint16 {
	return curveEdwards25519
}

func (c edwards25519Curve) pointEncode(p interface{}, compressed bool) []byte {
	return toEdwards25519Point(p).Bytes()
}

func (c edwards25519Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	var p edwards25519.Point
	_, err := p.SetBytes(b)
	if err != nil {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	if largeSubgroupCheck && !c.subgroupCheck(&p) {
		return nil, fmt.Errorf("point on %s is not in the large subgroup", c.params.name)
	}

	return &p, nil
}

func (c edwards25519Curve) pointCoordinates(_ interface{}) (*big.Int, *big.Int, error) {
	return nil, nil, fmt.Errorf("getting coordinates is not supported for Edwards25519")
}

func (c edwards25519Curve) pointAdd(p, q interface{}) interface{} {
	var r edwards25519.Point
	r.Add(toEdwards25519Point(p), toEdwards25519Point(q))

	return &r
}

func (c edwards25519Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	var ee [32]byte
	e.Value().FillBytes(ee[:])
	ReverseSlice(ee[:])
	var x edwards25519.Scalar
	_, err := x.SetCanonicalBytes(ee[:])
	if err != nil {
		panic("invalid scalar")
	}

	if constantTime {
		if basePoint {
			return (&edwards25519.Point{}).ScalarBaseMult(&x)
		} else {
			pp := toEdwards25519Point(p)
			return (&edwards25519.Point{}).ScalarMult(&x, pp)
		}
	} else {
		pp := toEdwards25519Point(p)
		return (&edwards25519.Point{}).VarTimeMultiScalarMult([]*edwards25519.Scalar{&x}, []*edwards25519.Point{pp})
	}
}

func (c edwards25519Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	pp := toEdwards25519Point(p)
	return (&edwards25519.Point{}).MultByCofactor(pp)
}

func (c edwards25519Curve) pointNegate(p interface{}) interface{} {
	var r edwards25519.Point
	r.Negate(toEdwards25519Point(p))

	return &r
}

func (c edwards25519Curve) pointIsPointAtInfinity(p interface{}) bool {
	return toEdwards25519Point(p).Equal(toEdwards25519Point(c.params.o.value)) == 1
}

func (c edwards25519Curve) pointIsInLargeSubgroup(p interface{}) bool {
	pp := toEdwards25519Point(p)

	return c.subgroupCheck(pp)
}

func (c edwards25519Curve) pointEquals(p, q interface{}) bool {
	return toEdwards25519Point(p).Equal(toEdwards25519Point(q)) == 1
}

func (c edwards25519Curve) subgroupCheck(p *edwards25519.Point) bool {
	var r edwards25519.Point
	r.VarTimeMultiScalarMult([]*edwards25519.Scalar{edwards25519ScMinusOne, edwards25519ScOne}, []*edwards25519.Point{p, p})

	return r.Equal(toEdwards25519Point(c.params.o.value)) == 1
}

func Edwards25519ToCurve25519(p Point) ([]byte, error) {
	if p.Curve().Name() != "ED-25519" {
		return nil, fmt.Errorf("not an ED-25519 point")
	}

	return toEdwards25519Point(p.value).BytesMontgomery(), nil
}

func Curve25519ToEdwards25519(curve25519PublicKey []byte) (Point, error) {
	var u field.Element
	_, err := u.SetBytes(curve25519PublicKey)
	if err != nil {
		return Point{}, fmt.Errorf("invalid Curve25519 point")
	}

	var zero, t1, t2 field.Element

	zero.Zero()
	t2.One()
	t1.Subtract(&u, &t2)
	t2.Add(&u, &t2)
	if t2.Equal(&zero) == 1 {
		// The birational equivalence is not defined for u = p-1
		return Point{}, fmt.Errorf("invalid Curve25519 point")
	}
	t2.Invert(&t2)
	t2.Multiply(&t1, &t2)

	return Edwards25519.DecodePoint(t2.Bytes(), true)
}
