package ec

import (
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"math/big"
)

type swCurveParams struct {
	name     string
	id       uint16
	impl     elliptic.Curve
	pLen     int
	g        Point
	o        Point
	zn       Field
	cofactor *big.Int
}

type swCurve struct {
	params *swCurveParams
}

func newSWCurve(impl elliptic.Curve) Curve {
	initFields()

	name := impl.Params().Name
	var id uint16
	switch name {
	case secp256k1.S256().Name:
		id = curveSecp256k1
	case elliptic.P224().Params().Name:
		id = curveP224
	case elliptic.P256().Params().Name:
		id = curveP256
	case elliptic.P384().Params().Name:
		id = curveP384
	case elliptic.P521().Params().Name:
		id = curveP521
	default:
		panic(fmt.Sprintf("missing id for curve: %s", name))
	}

	pLen := (impl.Params().BitSize + 7) / 8
	params := &swCurveParams{
		name: name,
		id:   id,
		impl: impl,
		pLen: pLen,
	}

	curve := swCurve{
		params: params,
	}

	gValue := make([]byte, 2*pLen)
	impl.Params().Gx.FillBytes(gValue[:pLen])
	impl.Params().Gy.FillBytes(gValue[pLen:])
	params.g = Point{
		curve:     curve,
		basePoint: true,
		value:     gValue,
	}

	oValue := make([]byte, 2*pLen)
	params.o = Point{
		curve: curve,
		value: oValue,
	}

	var err error
	params.zn, err = NewField(impl.Params().N)
	if err != nil {
		panic(fmt.Sprintf("field not initialized for modulus: %s", impl.Params().N.String()))
	}

	params.cofactor = big.NewInt(1)

	return curve
}

func toBytes(p interface{}) []byte {
	b, valid := p.([]byte)
	if !valid {
		panic("invalid internal point representation")
	}
	return b
}

func (c swCurve) Name() string {
	return c.params.name
}

func (c swCurve) Equals(o Curve) bool {
	return c.params.name == o.Name()
}

func (c swCurve) EncodedPointLength() int {
	return 1 + 2*c.params.pLen
}

func (c swCurve) EncodedCompressedPointLength() int {
	return 1 + c.params.pLen
}

func (c swCurve) DecodePoint(b []byte, largeSubgroupCheck bool) (Point, error) {
	p, err := c.pointDecode(b, largeSubgroupCheck)
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		value: p,
	}, nil
}

func (c swCurve) HashToPoint(message, domain []byte) (Point, error) {
	return Point{}, fmt.Errorf("hash to point is not supported for %s", c.Name())
}

func (c swCurve) NID() int {
	return int(c.params.id)
}

func (c swCurve) G() Point {
	return c.params.g
}

func (c swCurve) O() Point {
	return c.params.o
}

func (c swCurve) Zn() Field {
	return c.params.zn
}

func (c swCurve) Cofactor() *big.Int {
	return c.params.cofactor
}

func (c swCurve) SupportsECDSA() bool {
	return true
}
func (c swCurve) SupportsSchnorr() bool {
	return c.params.name == "secp256k1"
}

func (c swCurve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", c.params.name)
}

func (c swCurve) curveID() uint16 {
	return c.params.id
}

func (c swCurve) pointEncode(p interface{}, compressed bool) []byte {
	x, y, _ := c.pointCoordinates(p)

	if x.BitLen() == 0 && y.BitLen() == 0 {
		return []byte{0}
	}

	var b []byte
	if compressed {
		b = make([]byte, 1+c.params.pLen)
		if y.Bit(0) == 1 {
			b[0] = 3
		} else {
			b[0] = 2
		}
		x.FillBytes(b[1 : 1+c.params.pLen])
	} else {
		b = make([]byte, 1+2*c.params.pLen)
		b[0] = 4
		x.FillBytes(b[1 : 1+c.params.pLen])
		y.FillBytes(b[1+c.params.pLen : 1+2*c.params.pLen])
	}

	return b
}

func (c swCurve) pointDecode(b []byte, largeSubgroupCheck bool) (interface{}, error) {
	if len(b) == 1 && b[0] == 0 {
		p := make([]byte, 2*c.params.pLen)
		return p, nil
	}

	var x, y big.Int
	modulus := c.params.impl.Params().P

	if len(b) == 1+c.params.pLen && (b[0] == 2 || b[0] == 3) {
		x.SetBytes(b[1 : 1+c.params.pLen])
		y.Exp(&x, big.NewInt(3), modulus)
		if c.Name() != "secp256k1" {
			// a = -3 for P-224, P-256, P-384 and P-521 and 0 for secp256k1
			y.Sub(&y, &x)
			y.Sub(&y, &x)
			y.Sub(&y, &x)
		}
		y.Add(&y, c.params.impl.Params().B)
		y.ModSqrt(&y, modulus)

		if y.Bit(0) != uint(b[0]-2) {
			y.Sub(modulus, &y)
			y.Mod(&y, modulus)
		}
	} else if len(b) == 1+2*c.params.pLen && b[0] == 4 {
		x.SetBytes(b[1 : 1+c.params.pLen])
		y.SetBytes(b[1+c.params.pLen : 1+2*c.params.pLen])
	} else {
		return nil, fmt.Errorf("invalid point")
	}

	if x.Cmp(modulus) >= 0 || y.Cmp(modulus) >= 0 || !c.params.impl.IsOnCurve(&x, &y) {
		return nil, fmt.Errorf("invalid point")
	}

	p := make([]byte, 2*c.params.pLen)
	x.FillBytes(p[:c.params.pLen])
	y.FillBytes(p[c.params.pLen:])

	return p, nil
}

func (c swCurve) pointCoordinates(p interface{}) (*big.Int, *big.Int, error) {
	pp := toBytes(p)
	x := new(big.Int).SetBytes(pp[:c.params.pLen])
	y := new(big.Int).SetBytes(pp[c.params.pLen:])

	return x, y, nil
}

func (c swCurve) pointMultiply(p interface{}, e Scalar, basePoint, constantTime bool) interface{} {
	if constantTime {
		return c.pointMultiplyImpl(p, e.Encode(), basePoint, constantTime)
	} else {
		e1 := e.Value()
		res, ok := c.pointMultiplyWithSmallValues(p, e1)
		if ok {
			return res
		}
		e2 := new(big.Int).Sub(e1, c.params.impl.Params().N)

		encodedElement := make([]byte, e.Field().ByteLen())
		if e1.BitLen() <= e2.BitLen() {
			e1.FillBytes(encodedElement)
			return c.pointMultiplyImpl(p, encodedElement, basePoint, constantTime)
		} else {
			e2.Abs(e2)
			res, ok = c.pointMultiplyWithSmallValues(p, e2)
			if ok {
				return c.pointNegate(res)
			}

			e2.FillBytes(encodedElement)
			p2 := c.pointMultiplyImpl(p, encodedElement, basePoint, constantTime)
			return c.pointNegate(p2)
		}
	}
}

func (c swCurve) pointMultiplyByCofactor(p interface{}) interface{} {
	return p
}

func (c swCurve) pointMultiplyWithSmallValues(p interface{}, e *big.Int) (interface{}, bool) {
	if e.BitLen() == 0 {
		out := make([]byte, 2*c.params.pLen)
		return out, true
	} else if e.BitLen() == 1 {
		pp := toBytes(p)
		out := make([]byte, 2*c.params.pLen)
		copy(out, pp)
		return out, true
	} else if e.BitLen() == 2 && e.Bit(0) == 0 {
		return c.pointAdd(p, p), true
	} else {
		return nil, false
	}
}

func (c swCurve) pointNegate(p interface{}) interface{} {
	pp := toBytes(p)
	y := new(big.Int).SetBytes(pp[c.params.pLen:])
	y.Sub(c.params.impl.Params().P, y)
	y.Mod(y, c.params.impl.Params().P)

	out := make([]byte, 2*c.params.pLen)
	copy(out, pp)
	y.FillBytes(out[c.params.pLen:])
	return out
}

func (c swCurve) pointIsPointAtInfinity(p interface{}) bool {
	z := make([]byte, 2*c.params.pLen)
	return subtle.ConstantTimeCompare(z, toBytes(p)) == 1
}

func (c swCurve) pointIsInLargeSubgroup(_ interface{}) bool {
	return true
}

func (c swCurve) pointEquals(p, q interface{}) bool {
	pp := toBytes(p)
	qq := toBytes(q)
	return subtle.ConstantTimeCompare(pp, qq) == 1
}
