package ec

import (
	"bytes"
	"fmt"
	"math/big"
)

var (
	edwards377P, _  = new(big.Int).SetString("8444461749428370424248824938781546531375899335154063827935233455917409239041", 10)
	edwards377D, _  = new(big.Int).SetString("3021", 10)
	Edwards377Fp, _ = NewField(edwards377P)
)

type edwards377CurveParams struct {
	name     string
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type edwards377Curve struct {
	params *edwards377CurveParams
}

type edwards377Point struct {
	x, y, z, t *big.Int
}

func (p *edwards377Point) isPointAtInfinity() bool {
	pp := toEdwards377Point(p)
	return pp.x.BitLen() == 0 && pp.t.BitLen() == 0 && pp.y.Cmp(pp.z) == 0 && pp.z.BitLen() > 0
}

func (p *edwards377Point) affine() (x, y *big.Int) {
	zInv := new(big.Int).ModInverse(p.z, edwards377P)
	x = new(big.Int).Mul(p.x, zInv)
	y = new(big.Int).Mul(p.y, zInv)

	return x.Mod(x, edwards377P), y.Mod(y, edwards377P)
}

func newEdwards377() Curve {
	initFields()

	params := &edwards377CurveParams{
		name: "Edwards377",
	}

	curve := edwards377Curve{
		params: params,
	}

	gx, _ := new(big.Int).SetString("522678458525321116977504528531602186870683848189190546523208313015552693483", 10)
	gy, _ := new(big.Int).SetString("4625467284263880392848236339834904393692054417272076479096796531274999498606", 10)
	gt := new(big.Int).Mul(gx, gy)
	gt.Mod(gt, edwards377P)

	params.g = Point{
		curve:     curve,
		basePoint: true,
		value: &edwards377Point{
			x: gx,
			y: gy,
			z: big.NewInt(1),
			t: gt,
		},
	}

	params.o = Point{
		curve: curve,
		value: &edwards377Point{
			x: big.NewInt(0),
			y: big.NewInt(1),
			z: big.NewInt(1),
			t: big.NewInt(0),
		},
	}

	params.zn = fields[fieldEdwards377Zn]

	params.cofactor = big.NewInt(4)

	return curve
}

func toEdwards377Point(p interface{}) *edwards377Point {
	pp, valid := p.(*edwards377Point)
	if !valid {
		panic("invalid internal point representation")
	}
	return pp
}

func (j edwards377Curve) Name() string {
	return j.params.name
}

func (j edwards377Curve) Equals(o Curve) bool {
	return j.params.name == o.Name()
}

func (j edwards377Curve) EncodedPointLength() int {
	return 32
}

func (j edwards377Curve) EncodedCompressedPointLength() int {
	return 32
}

func (j edwards377Curve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := j.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: j,
		value: p,
	}, nil
}

func (j edwards377Curve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", j.params.name)
}

func (j edwards377Curve) NID() int {
	return 0
}

func (j edwards377Curve) G() Point {
	return j.params.g
}

func (j edwards377Curve) O() Point {
	return j.params.o
}

func (j edwards377Curve) Zn() Field {
	return j.params.zn
}

func (j edwards377Curve) Cofactor() *big.Int {
	return j.params.cofactor
}

func (j edwards377Curve) SupportsECDSA() bool {
	return false
}

func (j edwards377Curve) SupportsSchnorr() bool {
	return true
}

func (j edwards377Curve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", j.params.name)
}

func (j edwards377Curve) curveID() uint16 {
	return curveEdwards377
}

func (j edwards377Curve) pointEncode(p interface{}, compressed bool) []byte {
	x, y := toEdwards377Point(p).affine()

	if !compressed {
		buf := make([]byte, 64)
		x.FillBytes(buf[:32])
		ReverseSlice(buf[:32])
		y.FillBytes(buf[32:])
		ReverseSlice(buf[32:])
		return buf
	}

	yNeg := new(big.Int).Sub(edwards377P, y)
	isPositive := y.Cmp(yNeg) > 0

	buf := make([]byte, 32)
	x.FillBytes(buf)
	ReverseSlice(buf)
	if isPositive {
		buf[31] |= 0x80
	} else {
		buf[31] &= 0x7F
	}
	return buf
}

func (j edwards377Curve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	l := len(b)
	if l != 32 && l != 64 {
		return nil, fmt.Errorf("invalid point length")
	}

	var p edwards377Point

	if l == 64 { // Uncompressed
		bCopy := make([]byte, 64)
		if bytes.Equal(b, bCopy) {
			return j.O().value, nil
		}
		copy(bCopy, b)
		ReverseSlice(bCopy[:32])
		ReverseSlice(bCopy[32:])
		p.x = new(big.Int).SetBytes(bCopy[:32])
		if p.x.Cmp(edwards377P) >= 0 {
			return nil, fmt.Errorf("invalid x coordinate")
		}
		p.y = new(big.Int).SetBytes(bCopy[32:])
		if p.y.Cmp(edwards377P) >= 0 {
			return nil, fmt.Errorf("invalid y coordinate")
		}
	} else { // Compressed
		bCopy := make([]byte, 32)
		if bytes.Equal(b, bCopy) {
			return j.O().value, nil
		}
		copy(bCopy, b)

		isPositive := (bCopy[31] & 0x80) != 0x00
		bCopy[31] &= 0x7F

		ReverseSlice(bCopy)
		p.x = new(big.Int).SetBytes(bCopy)
		if p.x.Cmp(edwards377P) >= 0 {
			return nil, fmt.Errorf("invalid x coordinate")
		}

		// Compute y^2 = (-x^2 - 1) / (d*x^2 - 1)

		x2 := new(big.Int).Mul(p.x, p.x)
		x2.Mod(x2, edwards377P)

		y2 := new(big.Int).Neg(x2)
		y2.Sub(y2, big.NewInt(1))

		x2.Mul(x2, edwards377D)
		x2.Sub(x2, big.NewInt(1))
		if x2.BitLen() == 0 {
			return nil, fmt.Errorf("division by 0")
		}
		x2.ModInverse(x2, edwards377P)

		y2.Mul(y2, x2)
		y2.Mod(y2, edwards377P)

		p.y = new(big.Int).ModSqrt(y2, edwards377P)
		if p.y == nil {
			return nil, fmt.Errorf("y is not a square mod p")
		}

		yNeg := new(big.Int).Sub(edwards377P, p.y)
		if (p.y.Cmp(yNeg) > 0) != isPositive {
			p.y = yNeg
		}
	}

	p.z = big.NewInt(1)
	p.t = new(big.Int).Mul(p.x, p.y)
	p.t.Mod(p.t, edwards377P)

	if largeSubgroupCheck && !j.pointIsInLargeSubgroup(&p) {
		return nil, fmt.Errorf("point on %s is not in the large subgroup", j.params.name)
	}
	return &p, nil
}

func (j edwards377Curve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	pp := toEdwards377Point(p)
	x, y := pp.affine()
	return x, y, nil
}

func (j edwards377Curve) pointAdd(p, q interface{}) interface{} {
	pp := toEdwards377Point(p)
	qq := toEdwards377Point(q)

	var a, b, c, d, e, f, g, h big.Int
	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	t := new(big.Int).Set(pp.t)
	j.extendedAdd(x, y, z, t, qq.x, qq.y, qq.z, qq.t, &a, &b, &c, &d, &e, &f, &g, &h)

	return &edwards377Point{
		x: x,
		y: y,
		z: z,
		t: t,
	}
}

func (j edwards377Curve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	pp := toEdwards377Point(p)

	x := new(big.Int).Set(pp.x)
	y := new(big.Int).Set(pp.y)
	z := new(big.Int).Set(pp.z)
	t := new(big.Int).Set(pp.t)
	j.extendedMult(x, y, z, t, e.Value(), constantTime)

	return &edwards377Point{
		x: x,
		y: y,
		z: z,
		t: t,
	}
}

func (j edwards377Curve) pointMultiplyByCofactor(p interface{}) interface{} {
	p2 := j.pointAdd(p, p)
	return j.pointAdd(p2, p2)
}

func (j edwards377Curve) pointNegate(p interface{}) interface{} {
	pp := toEdwards377Point(p)

	return &edwards377Point{
		x: new(big.Int).Neg(pp.x),
		y: pp.y,
		z: pp.z,
		t: new(big.Int).Neg(pp.t),
	}
}

func (j edwards377Curve) pointIsPointAtInfinity(p interface{}) bool {
	return toEdwards377Point(p).isPointAtInfinity()
}

func (j edwards377Curve) pointIsInLargeSubgroup(p interface{}) bool {
	pp := toEdwards377Point(p)

	ppp := edwards377Point{
		x: new(big.Int).Set(pp.x),
		y: new(big.Int).Set(pp.y),
		z: new(big.Int).Set(pp.z),
		t: new(big.Int).Set(pp.t),
	}
	j.extendedMult(ppp.x, ppp.y, ppp.z, ppp.t, j.params.zn.Modulus(), false)
	return ppp.isPointAtInfinity()
}

func (j edwards377Curve) pointEquals(p, q interface{}) bool {
	pp := toEdwards377Point(p)
	qq := toEdwards377Point(q)

	var pxqz, qxpz, pyqz, qypz big.Int
	j.mulMod(&pxqz, pp.x, qq.z)
	j.mulMod(&qxpz, qq.x, pp.z)
	j.mulMod(&pyqz, pp.y, qq.z)
	j.mulMod(&qypz, qq.y, pp.z)

	return pxqz.Cmp(&qxpz) == 0 && pyqz.Cmp(&qypz) == 0
}

func (j edwards377Curve) extendedAdd(x1, y1, z1, t1, x2, y2, z2, t2 *big.Int, a, b, c, d, e, f, g, h *big.Int) {
	j.mulMod(a, x1, x2)
	j.mulMod(b, y1, y2)
	j.mulMod(c, t1, t2)
	j.mulMod(c, c, edwards377D)
	j.mulMod(d, z1, z2)
	e.Add(x1, y1)
	f.Add(x2, y2)
	j.mulMod(e, e, f)
	e.Sub(e, a)
	e.Sub(e, b)
	f.Sub(d, c)
	g.Add(d, c)
	h.Add(b, a)
	j.mulMod(x1, e, f)
	j.mulMod(y1, g, h)
	j.mulMod(z1, f, g)
	j.mulMod(t1, e, h)
}

func (j edwards377Curve) extendedMult(x1, y1, z1, t1 *big.Int, k *big.Int, constantTime bool) {
	var a, b, c, d, e, f, g, h big.Int
	x2, y2, z2, t2 := big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)

	bitLen := k.BitLen()
	if constantTime && bitLen < j.params.zn.Modulus().BitLen() {
		bitLen = j.params.zn.Modulus().BitLen()
	}

	for i := bitLen - 1; i >= 0; i-- {
		if k.Bit(i) == 0 {
			j.extendedAdd(x1, y1, z1, t1, x2, y2, z2, t2, &a, &b, &c, &d, &e, &f, &g, &h)
			j.extendedAdd(x2, y2, z2, t2, x2, y2, z2, t2, &a, &b, &c, &d, &e, &f, &g, &h)
		} else {
			j.extendedAdd(x2, y2, z2, t2, x1, y1, z1, t1, &a, &b, &c, &d, &e, &f, &g, &h)
			j.extendedAdd(x1, y1, z1, t1, x1, y1, z1, t1, &a, &b, &c, &d, &e, &f, &g, &h)
		}
	}

	x1.Set(x2)
	y1.Set(y2)
	z1.Set(z2)
	t1.Set(t2)
}

func (j edwards377Curve) mulMod(dst, a, b *big.Int) *big.Int {
	return dst.Mul(a, b).Mod(dst, edwards377P)
}
