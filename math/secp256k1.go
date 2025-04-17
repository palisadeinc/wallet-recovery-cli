package math

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

type s256Curve struct {
	*elliptic.CurveParams
}

var s256 s256Curve

func initS256() {
	s256.CurveParams = &elliptic.CurveParams{Name: "secp256k1"}
	s256.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
	s256.N, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16)
	s256.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)
	s256.Gx, _ = new(big.Int).SetString("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16)
	s256.Gy, _ = new(big.Int).SetString("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16)
	s256.BitSize = 256
}

// S256 returns a simple implementation of the secp256k1 elliptic curve.
// If performance or constant time operations are important then do not use this implementation.
func S256() elliptic.Curve {
	initonce.Do(initAll)
	return s256
}

func (curve s256Curve) Params() *elliptic.CurveParams {
	return curve.CurveParams
}

func (curve s256Curve) IsOnCurve(x, y *big.Int) bool {
	l := new(big.Int).Mul(y, y)
	l.Mod(l, curve.P)

	r := new(big.Int).Exp(x, big.NewInt(3), curve.P)
	r.Add(r, curve.B)
	r.Mod(r, curve.P)

	return l.Cmp(r) == 0
}

func (curve s256Curve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if x1.Cmp(y1) == 0 && x2.Cmp(y2) == 0 {
		return curve.Double(x1, y1)
	}

	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}

	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	yNeg := new(big.Int).Neg(y2)
	yNeg.Mod(yNeg, curve.P)
	if x1.Cmp(x2) == 0 && y1.Cmp(yNeg) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}

	tmp1 := new(big.Int).Sub(y2, y1)
	tmp2 := new(big.Int).Sub(x2, x1)
	tmp2.ModInverse(tmp2, curve.P)
	tmp1.Mul(tmp1, tmp2)
	tmp1.Mod(tmp1, curve.P)

	x = new(big.Int).Mul(tmp1, tmp1)
	x.Mod(x, curve.P)
	x.Sub(x, x1)
	x.Sub(x, x2)

	y = new(big.Int).Sub(x1, x)
	y.Mul(y, tmp1)
	y.Mod(y, curve.P)
	y.Sub(y, y1)

	return x.Mod(x, curve.P), y.Mod(y, curve.P)
}

func (curve s256Curve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	tmp1 := new(big.Int).Mul(x1, x1)
	tmp1.Mod(tmp1, curve.P)
	tmp1.Mul(tmp1, big.NewInt(3))
	tmp2 := new(big.Int).Add(y1, y1)
	tmp2.ModInverse(tmp2, curve.P)
	tmp1.Mul(tmp1, tmp2)
	tmp1.Mod(tmp1, curve.P)

	x = new(big.Int).Mul(tmp1, tmp1)
	x.Mod(x, curve.P)
	tmp2.Add(x1, x1)
	x.Sub(x, tmp2)

	y = new(big.Int).Sub(x1, x)
	y.Mul(y, tmp1)
	y.Mod(y, curve.P)
	y.Sub(y, y1)

	return x.Mod(x, curve.P), y.Mod(y, curve.P)
}

func (curve s256Curve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	kk := new(big.Int).SetBytes(k)
	kk = new(big.Int).Mod(kk, curve.P)

	x2, y2 := big.NewInt(0), big.NewInt(0)
	x3, y3 := new(big.Int).Set(x1), new(big.Int).Set(y1)

	for i := kk.BitLen() - 1; i >= 0; i-- {
		if kk.Bit(i) == 0 {
			x3, y3 = curve.Add(x3, y3, x2, y2)
			x2, y2 = curve.Double(x2, y2)
		} else {
			x2, y2 = curve.Add(x2, y2, x3, y3)
			x3, y3 = curve.Double(x3, y3)
		}
	}

	return x2, y2
}

func (curve s256Curve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func encodeElliptic(x1, y1 *big.Int, impl elliptic.Curve) []byte {
	if x1.BitLen() == 0 && y1.BitLen() == 0 {
		return []byte{0}
	}

	elementSize := (impl.Params().BitSize + 7) / 8

	b := make([]byte, 1+2*elementSize)
	b[0] = 4
	x1.FillBytes(b[1 : 1+elementSize])
	y1.FillBytes(b[1+elementSize : 1+2*elementSize])

	return b
}

func decodeElliptic(b []byte, impl elliptic.Curve) (x, y *big.Int, err error) {
	elementSize := (impl.Params().BitSize + 7) / 8
	if len(b) == 1 && b[0] == 0 {
		return big.NewInt(0), big.NewInt(0), nil
	} else {
		if len(b) != 1+2*elementSize {
			return nil, nil, fmt.Errorf("invalid input length")
		}
		if b[0] != 4 {
			return nil, nil, fmt.Errorf("invalid input type")
		}
		x = new(big.Int).SetBytes(b[1 : elementSize+1])
		y = new(big.Int).SetBytes(b[elementSize+1:])
	}

	if !impl.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point is not on the curve")
	}

	return x, y, nil
}
