package ec

import (
	"fmt"
	"math/big"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec/internal/curve448"
)

var curve448OrderScalar = [56]byte{243, 68, 88, 171, 146, 194, 120, 35, 85, 143, 197, 141, 114, 194, 108, 33, 144, 54, 214, 174, 73, 219, 78, 196, 233, 35, 202, 124, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 63}

type curve448CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type curve448Curve struct {
	params *curve448CurveParams
}

func newCurve448() Curve {
	initFields()

	params := &curve448CurveParams{
		name: "ED-448",
	}

	curve := curve448Curve{
		params: params,
	}

	g := &curve448.ProjectiveGroupElement{}
	curve448.GeGenerator(g)

	params.g = Point{
		curve: curve,
		value: g,
	}

	o := &curve448.ProjectiveGroupElement{}
	curve448.GeZero(o)

	params.o = Point{
		curve: curve,
		value: o,
	}

	params.zn = fields[fieldEdwards448Zn]

	params.cofactor = big.NewInt(4)

	return curve
}

func toCurve448Point(p interface{}) *curve448.ProjectiveGroupElement {
	pp, valid := p.(*curve448.ProjectiveGroupElement)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (c curve448Curve) Name() string {
	return c.params.name
}

func (c curve448Curve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c curve448Curve) EncodedPointLength() int {
	return 57
}

func (c curve448Curve) EncodedCompressedPointLength() int {
	return 57
}

func (c curve448Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c curve448Curve) NID() int {
	return 0
}

func (c curve448Curve) G() Point {
	return c.params.g
}

func (c curve448Curve) O() Point {
	return c.params.o
}

func (c curve448Curve) Zn() Field {
	return c.params.zn
}

func (c curve448Curve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c curve448Curve) SupportsECDSA() bool {
	return false
}

func (c curve448Curve) SupportsSchnorr() bool {
	return true
}

func (c curve448Curve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", c.params.name)
}

func (c curve448Curve) curveID() uint16 {
	return curveEdwards448
}

func (c curve448Curve) pointEncode(p interface{}, compressed bool) []byte {
	pp := toCurve448Point(p)

	var b [57]byte
	curve448.GeToBytes(&b, pp)

	return b[:]
}

func (c curve448Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	if len(b) != 57 {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	p := &curve448.ProjectiveGroupElement{}
	var s [57]byte
	copy(s[:], b[:])
	ok := curve448.GeFromBytes(p, &s)
	if !ok {
		return nil, fmt.Errorf("invalid %s point representation", c.params.name)
	}
	if largeSubgroupCheck && !c.subgroupCheck(p) {
		return nil, fmt.Errorf("point on %s is not in the large subgroup", c.params.name)
	}
	return p, nil
}

func (c curve448Curve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", c.Name())
}

func (c curve448Curve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	return nil, nil, fmt.Errorf("getting coordinates is not supported for %s", c.params.name)
}

func (c curve448Curve) pointAdd(p, q interface{}) interface{} {
	pp := toCurve448Point(p)
	qq := toCurve448Point(q)

	r := &curve448.ProjectiveGroupElement{}
	curve448.GeAdd(r, pp, qq)

	return r
}

func (c curve448Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	pp := toCurve448Point(p)

	var ee [56]byte
	e.Value().FillBytes(ee[:])
	ReverseSlice(ee[:])

	r := &curve448.ProjectiveGroupElement{}
	if constantTime {
		curve448.GeMul(r, pp, ee)
	} else {
		curve448.GeMulVarTime(r, pp, ee)
	}

	return r
}

func (c curve448Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	pp := toCurve448Point(p)

	r := &curve448.ProjectiveGroupElement{}
	curve448.GeDbl(r, pp)
	curve448.GeDbl(r, r)

	return r
}

func (c curve448Curve) pointNegate(p interface{}) interface{} {
	pp := toCurve448Point(p)

	r := &curve448.ProjectiveGroupElement{}
	curve448.GeNeg(r, pp)

	return r
}

func (c curve448Curve) pointIsPointAtInfinity(p interface{}) bool {
	pp := toCurve448Point(p)

	return curve448.GeIsZero(pp) == 1
}

func (c curve448Curve) pointIsInLargeSubgroup(p interface{}) bool {
	pp := toCurve448Point(p)

	return c.subgroupCheck(pp)
}

func (c curve448Curve) pointEquals(p, q interface{}) bool {
	pp := toCurve448Point(p)
	qq := toCurve448Point(q)

	r := &curve448.ProjectiveGroupElement{}
	curve448.GeNeg(r, pp)
	curve448.GeAdd(r, r, qq)

	return curve448.GeIsZero(r) == 1
}

func (c curve448Curve) subgroupCheck(p *curve448.ProjectiveGroupElement) bool {
	r := &curve448.ProjectiveGroupElement{}
	curve448.GeMulVarTime(r, p, curve448OrderScalar)

	return curve448.GeIsZero(r) == 1
}
