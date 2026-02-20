package ec

import (
	"bytes"
	"fmt"
	"math/big"
)

var (
	babyJubjubP, _  = new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495617", 10)
	babyJubjubA, _  = new(big.Int).SetString("168700", 10)
	babyJubjubD, _  = new(big.Int).SetString("168696", 10)
	BabyJubjubFp, _ = NewField(babyJubjubP)
)

type babyJubjubCurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type babyJubjubCurve struct {
	params *babyJubjubCurveParams
}

type babyJubjubPoint struct {
	x, y, z *big.Int
}

func (p *babyJubjubPoint) affine() (x, y *big.Int) {
	if p.x.BitLen() == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	zInv := new(big.Int).ModInverse(p.z, babyJubjubP)
	x = new(big.Int).Mul(p.x, zInv)
	y = new(big.Int).Mul(p.y, zInv)

	return x.Mod(x, babyJubjubP), y.Mod(y, babyJubjubP)
}

func newBabyJubjub() Curve {
	initFields()

	params := &babyJubjubCurveParams{
		name: "BabyJubjub",
	}

	curve := babyJubjubCurve{
		params: params,
	}

	gx, _ := new(big.Int).SetString("5299619240641551281634865583518297030282874472190772894086521144482721001553", 10)
	gy, _ := new(big.Int).SetString("16950150798460657717958625567821834550301663161624707787222815936182638968203", 10)

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value: &babyJubjubPoint{
			x: gx,
			y: gy,
			z: big.NewInt(1),
		},
	}

	params.o = Point{
		curve: curve,
		value: &babyJubjubPoint{
			x: big.NewInt(0),
			y: big.NewInt(1),
			z: big.NewInt(1),
		},
	}

	params.zn = fields[fieldBabyJubjubZn]

	params.cofactor = big.NewInt(8)

	return curve
}

func toBabyJubjubPoint(p interface{}) *babyJubjubPoint {
	pp, valid := p.(*babyJubjubPoint)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (j babyJubjubCurve) Name() string {
	return j.params.name
}

func (j babyJubjubCurve) Equals(o Curve) bool {
	return j.params.name == o.Name()
}

func (j babyJubjubCurve) EncodedPointLength() int {
	return 32
}

func (j babyJubjubCurve) EncodedCompressedPointLength() int {
	return 32
}

func (j babyJubjubCurve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := j.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: j,
		value: p,
	}, nil
}

func (j babyJubjubCurve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", j.params.name)
}

func (j babyJubjubCurve) NID() int {
	return 0
}

func (j babyJubjubCurve) G() Point {
	return j.params.g
}

func (j babyJubjubCurve) O() Point {
	return j.params.o
}

func (j babyJubjubCurve) Zn() Field {
	return j.params.zn
}

func (j babyJubjubCurve) Cofactor() *big.Int {
	return j.params.cofactor
}

func (j babyJubjubCurve) SupportsECDSA() bool {
	return false
}

func (j babyJubjubCurve) SupportsSchnorr() bool {
	return true
}

func (j babyJubjubCurve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", j.params.name)
}

func (j babyJubjubCurve) curveID() uint16 {
	return curveBabyJubjub
}

func (j babyJubjubCurve) pointEncode(p interface{}, compressed bool) []byte {
	x, y := toBabyJubjubPoint(p).affine()

	buf := make([]byte, 32)
	y.FillBytes(buf)
	ReverseSlice(buf)
	if x.Bit(0) == 1 {
		buf[31] |= 0x80
	}
	return buf
}

func (j babyJubjubCurve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	if len(b) != 32 {
		return nil, fmt.Errorf("invalid point length")
	}

	bCopy := make([]byte, 32)
	if bytes.Equal(b, bCopy) {
		return j.O().value, nil
	}
	copy(bCopy, b)

	sign := false
	if (bCopy[31] & 0x80) != 0x00 {
		sign = true
		bCopy[31] &= 0x7F
	}
	ReverseSlice(bCopy)
	x := big.NewInt(0)
	y := new(big.Int).SetBytes(bCopy)
	if y.Cmp(babyJubjubP) >= 0 {
		return nil, fmt.Errorf("invalid y coordinate")
	}
	z := big.NewInt(1)

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, babyJubjubP)
	xa := big.NewInt(1)
	xa.Sub(xa, y2)

	xb := new(big.Int).Mul(babyJubjubD, y2)
	xb.Mod(xb, babyJubjubP)
	xb.Sub(babyJubjubA, xb)

	if xb.BitLen() == 0 {
		return nil, fmt.Errorf("division by 0")
	}
	xb.ModInverse(xb, babyJubjubP)
	x.Mul(xa, xb)
	x.Mod(x, babyJubjubP)
	noSqrt := x.ModSqrt(x, babyJubjubP)
	if noSqrt == nil {
		return nil, fmt.Errorf("x is not a square mod p")
	}

	pointCoordSign := x.Bit(0) == 1
	if (sign && !pointCoordSign) || (!sign && pointCoordSign) {
		x.Neg(x)
		x.Mod(x, babyJubjubP)
	}

	p := &babyJubjubPoint{
		x: x,
		y: y,
		z: z,
	}

	if largeSubgroupCheck && !j.pointIsInLargeSubgroup(p) {
		return nil, fmt.Errorf("point on %s is not in the large subgroup", j.params.name)
	}
	return p, nil
}

func (j babyJubjubCurve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	x, y := toBabyJubjubPoint(p).affine()
	return x, y, nil
}

func (j babyJubjubCurve) pointAdd(p, q interface{}) interface{} {
	pp := toBabyJubjubPoint(p)
	qq := toBabyJubjubPoint(q)

	var a, b, c, d, e, f, g big.Int
	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	j.projectiveAdd(x, y, z, qq.x, qq.y, qq.z, &a, &b, &c, &d, &e, &f, &g)

	return &babyJubjubPoint{
		x: x,
		y: y,
		z: z,
	}
}

func (j babyJubjubCurve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	pp := toBabyJubjubPoint(p)

	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	j.projectiveMult(x, y, z, e.Value(), constantTime)

	return &babyJubjubPoint{
		x: x,
		y: y,
		z: z,
	}
}

func (j babyJubjubCurve) pointMultiplyByCofactor(p interface{}) interface{} {
	pp := toBabyJubjubPoint(p)

	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	j.projectiveMult(x, y, z, j.Cofactor(), false)

	return &babyJubjubPoint{
		x: x,
		y: y,
		z: z,
	}
}

func (j babyJubjubCurve) pointNegate(p interface{}) interface{} {
	pp := toBabyJubjubPoint(p)

	return &babyJubjubPoint{
		x: new(big.Int).Neg(pp.x),
		y: pp.y,
		z: pp.z,
	}
}

func (j babyJubjubCurve) pointIsPointAtInfinity(p interface{}) bool {
	pp := toBabyJubjubPoint(p)

	return pp.x.BitLen() == 0
}

func (j babyJubjubCurve) pointIsInLargeSubgroup(p interface{}) bool {
	pp := toBabyJubjubPoint(p)

	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	j.projectiveMult(x, y, z, j.params.zn.Modulus(), false)

	return x.BitLen() == 0
}

func (j babyJubjubCurve) pointEquals(p, q interface{}) bool {
	x1, y1 := toBabyJubjubPoint(p).affine()
	x2, y2 := toBabyJubjubPoint(q).affine()

	return x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0
}

func (j babyJubjubCurve) projectiveAdd(x1, y1, z1, x2, y2, z2 *big.Int, a, b, c, d, e, f, g *big.Int) {
	j.mulMod(a, z1, z2)
	j.mulMod(b, a, a)
	j.mulMod(c, x1, x2)
	j.mulMod(d, y1, y2)
	j.mulMod(e, babyJubjubD, c)
	j.mulMod(e, e, d)
	f.Sub(b, e)
	g.Add(b, e)
	b.Add(x1, y1)
	e.Add(x2, y2)
	j.mulMod(x1, b, e)
	x1.Sub(x1, c)
	x1.Sub(x1, d)
	j.mulMod(x1, x1, a)
	j.mulMod(x1, x1, f)
	j.mulMod(y1, babyJubjubA, c)
	y1.Sub(d, y1)
	j.mulMod(y1, y1, a)
	j.mulMod(y1, y1, g)
	j.mulMod(z1, f, g)
}

func (j babyJubjubCurve) projectiveMult(x1, y1, z1 *big.Int, k *big.Int, constantTime bool) {
	var a, b, c, d, e, f, g big.Int
	x2, y2, z2 := big.NewInt(0), big.NewInt(1), big.NewInt(1)

	bitLen := k.BitLen()
	if constantTime && bitLen < j.params.zn.Modulus().BitLen() {
		bitLen = j.params.zn.Modulus().BitLen()
	}

	for i := bitLen - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			j.projectiveAdd(x1, y1, z1, x2, y2, z2, &a, &b, &c, &d, &e, &f, &g)
			j.projectiveAdd(x2, y2, z2, x2, y2, z2, &a, &b, &c, &d, &e, &f, &g)
		} else {
			j.projectiveAdd(x2, y2, z2, x1, y1, z1, &a, &b, &c, &d, &e, &f, &g)
			j.projectiveAdd(x1, y1, z1, x1, y1, z1, &a, &b, &c, &d, &e, &f, &g)
		}
	}

	x1.Set(x2)
	y1.Set(y2)
	z1.Set(z2)
}

func (j babyJubjubCurve) mulMod(dst, a, b *big.Int) *big.Int {
	return dst.Mul(a, b).Mod(dst, babyJubjubP)
}
