package ec

import (
	"bytes"
	"fmt"
	"math/big"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type bls12381E2CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type bls12381E2Curve struct {
	params *bls12381E2CurveParams
}

func newBLS12381E2() Curve {
	initFields()

	params := &bls12381E2CurveParams{
		name: "BLS-12381-E2",
	}

	curve := bls12381E2Curve{
		params: params,
	}

	_, g, _, _ := bls12381.Generators()

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value:     &g,
	}

	var oAffine bls12381.G2Affine
	oBytes := make([]byte, bls12381.SizeOfG2AffineCompressed)
	oBytes[0] = 0b11000000
	dec := bls12381.NewDecoder(bytes.NewReader(oBytes))
	if err := dec.Decode(&oAffine); err != nil {
		panic(fmt.Sprintf("error initializing point at infinity: %s", err))
	}
	var oJac bls12381.G2Jac
	oJac.FromAffine(&oAffine)

	params.o = Point{
		curve: curve,
		value: &oJac,
	}

	params.zn = fields[fieldBLS12381Zn]

	params.cofactor, _ = new(big.Int).SetString("5d543a95414e7f1091d50792876a202cd91de4547085abaa68a205b2e5a7ddfa628f1cb4d9e82ef21537e293a6691ae1616ec6e786f0c70cf1c38e31c7238e5", 16)

	return curve
}

func toBLS12381E2Point(p interface{}) *bls12381.G2Jac {
	pp, valid := p.(*bls12381.G2Jac)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (c bls12381E2Curve) Name() string {
	return c.params.name
}

func (c bls12381E2Curve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c bls12381E2Curve) EncodedPointLength() int {
	return bls12381.SizeOfG2AffineUncompressed
}

func (c bls12381E2Curve) EncodedCompressedPointLength() int {
	return bls12381.SizeOfG2AffineCompressed
}

func (c bls12381E2Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c bls12381E2Curve) HashToPoint(message, domain []byte) (Point, error) {
	pAffine, err := bls12381.HashToG2(message, domain)
	if err != nil {
		return Point{}, fmt.Errorf("error hashing to %s: %s", c.params.name, err)
	}

	var pJac bls12381.G2Jac
	pJac.FromAffine(&pAffine)

	return Point{
		curve: BLS12381E2,
		value: &pJac,
	}, nil
}

func (c bls12381E2Curve) NID() int {
	return 0
}

func (c bls12381E2Curve) G() Point {
	return c.params.g
}

func (c bls12381E2Curve) O() Point {
	return c.params.o
}

func (c bls12381E2Curve) Zn() Field {
	return c.params.zn
}

func (c bls12381E2Curve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c bls12381E2Curve) SupportsECDSA() bool {
	return false
}

func (c bls12381E2Curve) SupportsSchnorr() bool {
	return false
}

func (c bls12381E2Curve) PairingCurve() (PairingCurve, error) {
	return BLS12381, nil
}

func (c bls12381E2Curve) curveID() uint16 {
	return curveBLS12381E2
}

func (c bls12381E2Curve) pointEncode(p interface{}, compressed bool) []byte {
	var pAffine bls12381.G2Affine
	pAffine.FromJacobian(toBLS12381E2Point(p))
	if compressed {
		res := pAffine.Bytes()
		return res[:]
	} else {
		res := pAffine.RawBytes()
		return res[:]
	}
}

func (c bls12381E2Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	var pAffine bls12381.G2Affine
	_, err := pAffine.SetBytes(b)
	if err != nil {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	if !pAffine.IsOnCurve() {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	if largeSubgroupCheck && !pAffine.IsInSubGroup() {
		return nil, fmt.Errorf("point on %s is not in the large subgroup", c.params.name)
	}

	var pJac bls12381.G2Jac
	pJac.FromAffine(&pAffine)

	return &pJac, nil
}

func (c bls12381E2Curve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	return nil, nil, fmt.Errorf("getting coordinates is not supported for curve %s", c.params.name)
}

func (c bls12381E2Curve) pointAdd(p, q interface{}) interface{} {
	var r bls12381.G2Jac
	r.Set(toBLS12381E2Point(p)).AddAssign(toBLS12381E2Point(q))

	return &r
}

func (c bls12381E2Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	var r bls12381.G2Jac
	r.ScalarMultiplication(toBLS12381E2Point(p), e.Value())

	return &r
}

func (c bls12381E2Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	var r bls12381.G2Jac
	r.ScalarMultiplication(toBLS12381E2Point(p), c.params.cofactor)

	return &r
}

func (c bls12381E2Curve) pointNegate(p interface{}) interface{} {
	var r bls12381.G2Jac
	r.Neg(toBLS12381E2Point(p))

	return &r
}

func (c bls12381E2Curve) pointIsPointAtInfinity(p interface{}) bool {
	return toBLS12381E2Point(p).Equal(toBLS12381E2Point(c.params.o.value))
}

func (c bls12381E2Curve) pointIsInLargeSubgroup(p interface{}) bool {
	return toBLS12381E2Point(p).IsInSubGroup()
}

func (c bls12381E2Curve) pointEquals(p, q interface{}) bool {
	return toBLS12381E2Point(p).Equal(toBLS12381E2Point(q))
}
