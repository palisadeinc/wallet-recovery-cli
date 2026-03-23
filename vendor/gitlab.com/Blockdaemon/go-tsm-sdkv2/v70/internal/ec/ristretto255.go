package ec

import (
	"fmt"
	"math/big"

	"github.com/gtank/ristretto255"
)

var (
	ristretto255ScOne      *ristretto255.Scalar
	ristretto255ScMinusOne *ristretto255.Scalar
)

type ristretto255CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type ristretto255Curve struct {
	params *ristretto255CurveParams
}

func newRistretto255() Curve {
	initFields()

	params := &ristretto255CurveParams{
		name: "Ristretto255",
	}

	curve := ristretto255Curve{
		params: params,
	}

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value:     ristretto255.NewGeneratorElement(),
	}

	params.o = Point{
		curve: curve,
		value: ristretto255.NewIdentityElement(),
	}

	params.zn = fields[fieldEdwards25519Zn]

	ristretto255ScOne = ristretto255.NewScalar()
	ristretto255ScMinusOne = ristretto255.NewScalar()

	_, _ = ristretto255ScOne.SetCanonicalBytes([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	_, _ = ristretto255ScMinusOne.SetCanonicalBytes([]byte{236, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16})

	params.cofactor = big.NewInt(1)

	return curve
}

func toRistretto255Point(p interface{}) *ristretto255.Element {
	pp, valid := p.(*ristretto255.Element)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (c ristretto255Curve) Name() string {
	return c.params.name
}

func (c ristretto255Curve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c ristretto255Curve) EncodedPointLength() int {
	return 32
}

func (c ristretto255Curve) EncodedCompressedPointLength() int {
	return 32
}

func (c ristretto255Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c ristretto255Curve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", c.Name())
}

func (c ristretto255Curve) NID() int {
	return 0
}

func (c ristretto255Curve) G() Point {
	return c.params.g
}

func (c ristretto255Curve) O() Point {
	return c.params.o
}

func (c ristretto255Curve) Zn() Field {
	return c.params.zn
}

func (c ristretto255Curve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c ristretto255Curve) SupportsECDSA() bool {
	return false
}

func (c ristretto255Curve) SupportsSchnorr() bool {
	return true
}

func (c ristretto255Curve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", c.params.name)
}

func (c ristretto255Curve) curveID() uint16 {
	return curveRistretto256
}

func (c ristretto255Curve) pointEncode(p interface{}, compressed bool) []byte {
	return toRistretto255Point(p).Bytes()
}

func (c ristretto255Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	var p ristretto255.Element
	_, err := p.SetCanonicalBytes(b)
	if err != nil {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	return &p, nil
}

func (c ristretto255Curve) pointCoordinates(_ interface{}) (*big.Int, *big.Int, error) {
	return nil, nil, fmt.Errorf("getting coordinates is not supported for Ristretto255")
}

func (c ristretto255Curve) pointAdd(p, q interface{}) interface{} {
	var r ristretto255.Element
	r.Add(toRistretto255Point(p), toRistretto255Point(q))

	return &r
}

func (c ristretto255Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	var ee [32]byte
	e.Value().FillBytes(ee[:])
	ReverseSlice(ee[:])
	var x ristretto255.Scalar
	_, err := x.SetCanonicalBytes(ee[:])
	if err != nil {
		panic("invalid scalar")
	}

	if constantTime {
		if basePoint {
			r := ristretto255.NewIdentityElement().ScalarBaseMult(&x)
			return r
		} else {
			r := ristretto255.NewIdentityElement().ScalarMult(&x, toRistretto255Point(p))
			return r
		}
	} else {
		pp := toRistretto255Point(p)
		return ristretto255.NewIdentityElement().VarTimeMultiScalarMult([]*ristretto255.Scalar{&x}, []*ristretto255.Element{pp})
	}
}

func (c ristretto255Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	return p
}

func (c ristretto255Curve) pointNegate(p interface{}) interface{} {
	var r ristretto255.Element
	r.Negate(toRistretto255Point(p))

	return &r
}

func (c ristretto255Curve) pointIsPointAtInfinity(p interface{}) bool {
	return toRistretto255Point(p).Equal(toRistretto255Point(c.params.o.value)) == 1
}

func (c ristretto255Curve) pointIsInLargeSubgroup(p interface{}) bool {
	return true
}

func (c ristretto255Curve) pointEquals(p, q interface{}) bool {
	return toRistretto255Point(p).Equal(toRistretto255Point(q)) == 1
}
