package ec

import (
	"bytes"
	"crypto/elliptic"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var (
	pModulus, _     = new(big.Int).SetString("28948022309329048855892746252171976963363056481941560715954676764349967630337", 10)
	PallasMinaFp, _ = NewField(pModulus)
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
	params        *swCurveParams
	hasNativeImpl bool
}

func newSWCurve(impl elliptic.Curve) Curve {
	initFields()

	name := impl.Params().Name
	var curveID uint16
	var fieldID uint16
	var hasNativeImpl bool
	switch name {
	case secp256k1.S256().Name:
		curveID = curveSecp256k1
		fieldID = fieldSecp256k1Zn
		hasNativeImpl = true
	case elliptic.P224().Params().Name:
		curveID = curveP224
		fieldID = fieldP224Zn
		hasNativeImpl = true
	case elliptic.P256().Params().Name:
		curveID = curveP256
		fieldID = fieldP256Zn
		hasNativeImpl = true
	case elliptic.P384().Params().Name:
		curveID = curveP384
		fieldID = fieldP384Zn
		hasNativeImpl = true
	case elliptic.P521().Params().Name:
		curveID = curveP521
		fieldID = fieldP521Zn
		hasNativeImpl = true
	case "StarkCurve":
		curveID = curveStarkCurve
		fieldID = fieldStarkCurveZn
		hasNativeImpl = false
	case "PallasMina":
		curveID = curvePallasMina
		fieldID = fieldPallasZn
		hasNativeImpl = false
	default:
		panic(fmt.Sprintf("missing id for curve: %s", name))
	}

	pLen := (impl.Params().BitSize + 7) / 8
	params := &swCurveParams{
		name: name,
		id:   curveID,
		impl: impl,
		pLen: pLen,
	}

	curve := swCurve{
		params:        params,
		hasNativeImpl: hasNativeImpl,
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
	params.zn, err = newFieldFromID(fieldID)
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
	switch c.Name() {
	case "PallasMina":
		return 32
	default:
		return 1 + 2*c.params.pLen
	}
}

func (c swCurve) EncodedCompressedPointLength() int {
	switch c.Name() {
	case "PallasMina":
		return 32
	default:
		return 1 + c.params.pLen
	}
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
	return c.params.name == "secp256k1" || c.params.name == "PallasMina"
}

func (c swCurve) PairingCurve() (PairingCurve, error) {
	return nil, fmt.Errorf("pairings are not supported for %s", c.params.name)
}

func (c swCurve) curveID() uint16 {
	return c.params.id
}

func (c swCurve) pointEncode(p interface{}, compressed bool) []byte {
	x, y, _ := c.pointCoordinates(p)

	if c.Name() == "PallasMina" {
		return pointEncodePallasMina(x, y)
	}

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
	if c.Name() == "PallasMina" {
		var err error
		b, err = pointParsePallasMina(b)
		if err != nil {
			return nil, err
		}
	}

	if len(b) == 1 && b[0] == 0 {
		p := make([]byte, 2*c.params.pLen)
		return p, nil
	}

	var x, y big.Int
	modulus := c.params.impl.Params().P

	if len(b) == 1+c.params.pLen && (b[0] == 2 || b[0] == 3) {
		x.SetBytes(b[1 : 1+c.params.pLen])
		y.Exp(&x, big.NewInt(3), modulus)
		switch c.Name() {
		case "P-224", "P-256", "P-384", "P-521":
			// a = -3 for P-224, P-256, P-384 and P-521
			y.Sub(&y, &x)
			y.Sub(&y, &x)
			y.Sub(&y, &x)
		case "StarkCurve":
			// a = 1 for StarkCurve
			y.Add(&y, &x)
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
		return c.pointMultiplyInner(p, e.Encode(), basePoint, constantTime)
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
			return c.pointMultiplyInner(p, encodedElement, basePoint, constantTime)
		} else {
			e2.Abs(e2)
			res, ok = c.pointMultiplyWithSmallValues(p, e2)
			if ok {
				return c.pointNegate(res)
			}

			e2.FillBytes(encodedElement)
			p2 := c.pointMultiplyInner(p, encodedElement, basePoint, constantTime)
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

func (c swCurve) pointAddGeneric(p, q interface{}) interface{} {
	x1, y1, _ := c.pointCoordinates(p)
	x2, y2, _ := c.pointCoordinates(q)

	x, y := c.params.impl.Add(x1, y1, x2, y2)
	return swXYToValue(x, y, c.params.pLen)
}

func (c swCurve) pointMultiplyGeneric(p interface{}, e []byte, basePoint, constantTime bool) interface{} {
	var x, y *big.Int
	if basePoint {
		x, y = c.params.impl.ScalarBaseMult(e)
	} else {
		x1, y1, _ := c.pointCoordinates(p)
		x, y = c.params.impl.ScalarMult(x1, y1, e)
	}

	return swXYToValue(x, y, c.params.pLen)
}

func swXYToValue(x, y *big.Int, byteSize int) []byte {
	b := make([]byte, 2*byteSize)

	if x.BitLen() == 0 && y.BitLen() == 0 {
		return b
	}

	x.FillBytes(b[:byteSize])
	y.FillBytes(b[byteSize:])

	return b
}

func pointEncodePallasMina(x, y *big.Int) []byte {
	if x.BitLen() == 0 && y.BitLen() == 0 {
		return make([]byte, 32)
	}
	xBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	ReverseSlice(xBytes)
	xBytes[31] |= (byte)(y.Bit(0) << 7)
	return xBytes
}

func pointParsePallasMina(p []byte) ([]byte, error) {
	if len(p) != 32 {
		return nil, fmt.Errorf("invalid point")
	}

	buffer := make([]byte, 33)
	if bytes.Equal(p, buffer[:32]) {
		return []byte{0}, nil
	}
	copy(buffer[1:], p)
	signBit := (buffer[32] >> 7) & 1
	buffer[0] = 2 + signBit
	buffer[32] &= 0x7F
	ReverseSlice(buffer[1:])

	return buffer, nil
}
