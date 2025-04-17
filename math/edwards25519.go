package math

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type edwards25519Curve struct {
	*elliptic.CurveParams
}

var edwards25519 edwards25519Curve

func initEdwards25519() {
	edwards25519.CurveParams = &elliptic.CurveParams{Name: "ED-25519"}
	edwards25519.P, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	edwards25519.N, _ = new(big.Int).SetString("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16)
	edwards25519.B, _ = new(big.Int).SetString("52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3", 16)
	edwards25519.Gx, _ = new(big.Int).SetString("216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a", 16)
	edwards25519.Gy, _ = new(big.Int).SetString("6666666666666666666666666666666666666666666666666666666666666658", 16)
	edwards25519.BitSize = 256
}

// Edwards25519 returns a simple implementation of the Edwards 25519 elliptic curve.
// If performance or constant time operations are important then do not use this implementation.
func Edwards25519() elliptic.Curve {
	initonce.Do(initAll)
	return edwards25519
}

func (curve edwards25519Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve edwards25519Curve) IsOnCurve(x, y *big.Int) bool {
	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, curve.P)

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, curve.P)

	l := new(big.Int).Sub(y2, x2)
	l.Mod(l, curve.P)

	r := new(big.Int).Mul(curve.B, x2)
	r.Mod(r, curve.P)
	r.Mul(r, y2)
	r.Mod(r, curve.P)
	r.Add(big.NewInt(1), r)
	r.Mod(r, curve.P)

	return l.Cmp(r) == 0
}

func (curve edwards25519Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	x1y2 := new(big.Int).Mul(x1, y2)
	x1y2.Mod(x1y2, curve.P)

	y1x2 := new(big.Int).Mul(y1, x2)
	y1x2.Mod(y1x2, curve.P)

	x1x2 := new(big.Int).Mul(x1, x2)
	x1x2.Mod(x1x2, curve.P)

	y1y2 := new(big.Int).Mul(y1, y2)
	y1y2.Mod(y1y2, curve.P)

	dx1x2y1y2 := new(big.Int).Mul(curve.B, x1x2)
	dx1x2y1y2.Mod(dx1x2y1y2, curve.P)
	dx1x2y1y2.Mul(dx1x2y1y2, y1y2)
	dx1x2y1y2.Mod(dx1x2y1y2, curve.P)

	// X

	numerator := new(big.Int).Add(x1y2, y1x2)
	denominator := new(big.Int).Add(big.NewInt(1), dx1x2y1y2)
	denominator.ModInverse(denominator, curve.P)

	x = new(big.Int).Mul(numerator, denominator)
	x.Mod(x, curve.P)

	// Y

	numerator = numerator.Add(x1x2, y1y2)
	denominator.Sub(big.NewInt(1), dx1x2y1y2)
	denominator.ModInverse(denominator, curve.P)

	y = new(big.Int).Mul(numerator, denominator)
	y.Mod(y, curve.P)

	return x, y
}

func (curve edwards25519Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	x1x1 := new(big.Int).Mul(x1, x1)
	x1x1.Mod(x1x1, curve.P)

	y1y1 := new(big.Int).Mul(y1, y1)
	y1y1.Mod(y1y1, curve.P)

	// X

	numerator := new(big.Int).Mul(big.NewInt(2), x1)
	numerator.Mul(numerator, y1)
	numerator.Mod(numerator, curve.P)
	denominator := new(big.Int).Sub(y1y1, x1x1)
	denominator.ModInverse(denominator, curve.P)

	x = new(big.Int).Mul(numerator, denominator)
	x.Mod(x, curve.P)

	// Y

	numerator = numerator.Add(y1y1, x1x1)
	denominator.Add(big.NewInt(2), x1x1)
	denominator.Sub(denominator, y1y1)
	denominator.ModInverse(denominator, curve.P)

	y = new(big.Int).Mul(numerator, denominator)
	y.Mod(y, curve.P)

	return x, y

}

func (curve edwards25519Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	kk := new(big.Int).SetBytes(k)
	kk.Mod(kk, curve.N)

	r0x, r0y := big.NewInt(0), big.NewInt(1)
	r1x, r1y := new(big.Int).Set(x1), new(big.Int).Set(y1)

	for i := kk.BitLen() - 1; i >= 0; i-- {
		if kk.Bit(i) == 0 {
			r1x, r1y = curve.Add(r1x, r1y, r0x, r0y)
			r0x, r0y = curve.Double(r0x, r0y)
		} else {
			r0x, r0y = curve.Add(r0x, r0y, r1x, r1y)
			r1x, r1y = curve.Double(r1x, r1y)
		}
	}

	return r0x, r0y
}

func (curve edwards25519Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func encodeEdwards25519(x1, y1 *big.Int) []byte {
	b := make([]byte, 32)
	y1.FillBytes(b)
	if x1.Bit(0) == 1 {
		b[0] = b[0] | 0x80
	}
	reverseSlice(b)
	return b
}

func decodeEdwards25519(b []byte) (x, y *big.Int, err error) {
	if len(b) != 32 {
		return nil, nil, fmt.Errorf("invalid input lenght")
	}

	bb := make([]byte, len(b))
	copy(bb, b)
	reverseSlice(bb)
	xBit := bb[0]&0x80 != 0
	bb[0] = bb[0] & 0x7F
	y = new(big.Int).SetBytes(bb)
	y.Mod(y, edwards25519.P)

	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, edwards25519.P)

	// u = y^2 - 1
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, edwards25519.P)

	// v = d y^2 + 1.
	v := new(big.Int).Mul(y2, edwards25519.B)
	v.Mod(v, edwards25519.P)
	v.Add(v, big.NewInt(1))
	v.Mod(v, edwards25519.P)

	//          (p+3)/8      3        (p-5)/8
	// x = (u/v)        = u v  (u v^7)         (mod p)

	uv3 := new(big.Int).Exp(v, big.NewInt(3), edwards25519.P)
	uv3.Mul(u, uv3)
	uv3.Mod(uv3, edwards25519.P)

	uv7 := new(big.Int).Exp(v, big.NewInt(7), edwards25519.P)
	uv7.Mul(u, uv7)
	uv7.Mod(uv7, edwards25519.P)

	exp := new(big.Int).Sub(edwards25519.P, big.NewInt(5))
	exp.Div(exp, big.NewInt(8))

	uv7.Exp(uv7, exp, edwards25519.P)

	x = new(big.Int).Mul(uv3, uv7)
	x.Mod(x, edwards25519.P)

	// Compute x

	x2 := new(big.Int).Mul(x, x)
	x2.Mod(x2, edwards25519.P)
	x2.Mul(x2, v)
	x2.Mod(x2, edwards25519.P)

	if x2.Cmp(u) != 0 {
		negU := new(big.Int).Neg(u)
		negU.Mod(negU, edwards25519.P)
		if x2.Cmp(negU) != 0 {
			return nil, nil, fmt.Errorf("no square root exist")
		}
		// x = x * 2^((p-1)/4)

		exp.Sub(edwards25519.P, big.NewInt(1))
		exp.Div(exp, big.NewInt(4))
		tmp := new(big.Int).Exp(big.NewInt(2), exp, edwards25519.P)

		x.Mul(x, tmp)
		x.Mod(x, edwards25519.P)
	}

	// Select the right x value depending on the sign bit

	if (xBit && x.Bit(0) == 0) || (!xBit && x.Bit(0) == 1) {
		x.Sub(edwards25519.P, x)
		x.Mod(x, edwards25519.P)
	}

	if !edwards25519.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point is not on the curve")
	}

	return x, y, nil
}

func reverseSlice(b []byte) {
	l := len(b)
	for i := 0; i < l/2; i++ {
		tt := b[i]
		b[i] = b[l-1-i]
		b[l-1-i] = tt
	}
}
