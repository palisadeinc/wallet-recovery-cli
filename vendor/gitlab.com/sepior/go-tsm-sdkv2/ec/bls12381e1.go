package ec

import (
	"bytes"
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"math/big"
)

type bls12381E1CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type bls12381E1Curve struct {
	params *bls12381E1CurveParams
}

func newBLS12381E1() Curve {
	initFields()

	params := &bls12381E1CurveParams{
		name: "BLS-12381-E1",
	}

	curve := bls12381E1Curve{
		params: params,
	}

	g, _, _, _ := bls12381.Generators()

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value:     &g,
	}

	var oAffine bls12381.G1Affine
	oBytes := make([]byte, bls12381.SizeOfG1AffineCompressed)
	oBytes[0] = 0b11000000
	dec := bls12381.NewDecoder(bytes.NewReader(oBytes))
	if err := dec.Decode(&oAffine); err != nil {
		panic(fmt.Sprintf("error initializing point at infinity: %s", err))
	}
	var oJac bls12381.G1Jac
	oJac.FromAffine(&oAffine)

	params.o = Point{
		curve: curve,
		value: &oJac,
	}

	params.zn = fields[fieldBLS12381Zn]

	params.cofactor, _ = new(big.Int).SetString("396c8c005555e1568c00aaab0000aaab", 16)

	return curve
}

func toBLS12381E1Point(p interface{}) *bls12381.G1Jac {
	pp, valid := p.(*bls12381.G1Jac)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (c bls12381E1Curve) Name() string {
	return c.params.name
}

func (c bls12381E1Curve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c bls12381E1Curve) EncodedPointLength() int {
	return bls12381.SizeOfG1AffineUncompressed
}

func (c bls12381E1Curve) EncodedCompressedPointLength() int {
	return bls12381.SizeOfG1AffineCompressed
}

func (c bls12381E1Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c bls12381E1Curve) HashToPoint(message, domain []byte) (Point, error) {
	pAffine, err := bls12381.HashToG1(message, domain)
	if err != nil {
		return Point{}, fmt.Errorf("error hashing to %s: %s", c.params.name, err)
	}

	var pJac bls12381.G1Jac
	pJac.FromAffine(&pAffine)

	return Point{
		curve: BLS12381E1,
		value: &pJac,
	}, nil
}

func (c bls12381E1Curve) NID() int {
	return 0
}

func (c bls12381E1Curve) G() Point {
	return c.params.g
}

func (c bls12381E1Curve) O() Point {
	return c.params.o
}

func (c bls12381E1Curve) Zn() Field {
	return c.params.zn
}

func (c bls12381E1Curve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c bls12381E1Curve) SupportsECDSA() bool {
	return false
}

func (c bls12381E1Curve) SupportsSchnorr() bool {
	return false
}

func (c bls12381E1Curve) PairingCurve() (PairingCurve, error) {
	return BLS12381, nil
}

func (c bls12381E1Curve) curveID() uint16 {
	return curveBLS12381E1
}

func (c bls12381E1Curve) pointEncode(p interface{}, compressed bool) []byte {
	var pAffine bls12381.G1Affine
	pAffine.FromJacobian(toBLS12381E1Point(p))
	if compressed {
		res := pAffine.Bytes()
		return res[:]
	} else {
		res := pAffine.RawBytes()
		return res[:]
	}
}

func (c bls12381E1Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	var pAffine bls12381.G1Affine
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
	var pJac bls12381.G1Jac
	pJac.FromAffine(&pAffine)

	return &pJac, nil
}

func (c bls12381E1Curve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	var pAffine bls12381.G1Affine
	pAffine.FromJacobian(toBLS12381E1Point(p))

	return pAffine.X.BigInt(new(big.Int)), pAffine.Y.BigInt(new(big.Int)), nil
}

func (c bls12381E1Curve) pointAdd(p, q interface{}) interface{} {
	var r bls12381.G1Jac
	r.Set(toBLS12381E1Point(p)).AddAssign(toBLS12381E1Point(q))

	return &r
}

func (c bls12381E1Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	var r bls12381.G1Jac
	r.ScalarMultiplication(toBLS12381E1Point(p), e.Value())

	return &r
}

func (c bls12381E1Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	var r bls12381.G1Jac
	r.ScalarMultiplication(toBLS12381E1Point(p), c.params.cofactor)

	return &r
}

func (c bls12381E1Curve) pointNegate(p interface{}) interface{} {
	var r bls12381.G1Jac
	r.Neg(toBLS12381E1Point(p))

	return &r
}

func (c bls12381E1Curve) pointIsPointAtInfinity(p interface{}) bool {
	return toBLS12381E1Point(p).Equal(toBLS12381E1Point(c.params.o.value))
}

func (c bls12381E1Curve) pointIsInLargeSubgroup(p interface{}) bool {
	return toBLS12381E1Point(p).IsInSubGroup()
}

func (c bls12381E1Curve) pointEquals(p, q interface{}) bool {
	return toBLS12381E1Point(p).Equal(toBLS12381E1Point(q))
}
