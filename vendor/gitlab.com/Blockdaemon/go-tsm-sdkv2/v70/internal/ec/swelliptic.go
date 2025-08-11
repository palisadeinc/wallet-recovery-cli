package ec

import (
	"crypto/elliptic"
	"math/big"
)

var zero = big.NewInt(0)
var one = big.NewInt(1)

type swEllipticCurve struct {
	a, b   *big.Int
	params *elliptic.CurveParams
}

func (e *swEllipticCurve) Params() *elliptic.CurveParams {
	return e.params
}

func (e *swEllipticCurve) IsOnCurve(x, y *big.Int) bool {
	r := new(big.Int).Exp(x, big.NewInt(3), e.params.P)
	tmp := new(big.Int).Mul(e.a, x)
	r.Add(r, tmp)
	r.Add(r, e.b)
	r.Mod(r, e.params.P)

	l := tmp.Mul(y, y)
	l.Mod(l, e.params.P)

	return l.Cmp(r) == 0
}

func (e *swEllipticCurve) Add(x1, y1, x2, y2 *big.Int) (x, y *big.Int) {
	if x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Cmp(zero) == 0 && y2.Cmp(zero) == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		return e.Double(x1, y1)
	}
	b := newArithmeticBuffer()
	x = new(big.Int)
	y = new(big.Int)
	z := new(big.Int)

	b.h.Sub(x2, x1)
	e.mulMod(b.hh, b.h, b.h)
	b.i.Lsh(b.hh, 2)
	e.mulMod(b.j, b.h, b.i)
	b.t0.Sub(y2, y1)
	b.r.Lsh(b.t0, 1)
	e.mulMod(b.v, x1, b.i)
	e.mulMod(b.t0, b.r, b.r)
	b.t1.Lsh(b.v, 1)
	b.t0.Sub(b.t0, b.j)
	x.Sub(b.t0, b.t1)
	b.t0.Sub(b.v, x)
	e.mulMod(b.t1, y1, b.j)
	b.t1.Lsh(b.t1, 1)
	e.mulMod(b.t0, b.r, b.t0)
	y.Sub(b.t0, b.t1)
	z.Lsh(b.h, 1)
	e.scale(b.t0, b.t1, x, y, z)
	return x, y
}

func (e *swEllipticCurve) Double(x1, y1 *big.Int) (x, y *big.Int) {
	if x1.Cmp(zero) == 0 && y1.Cmp(zero) == 0 {
		return big.NewInt(0), big.NewInt(0)
	}
	b := newArithmeticBuffer()
	x = new(big.Int)
	y = new(big.Int)
	z := new(big.Int)

	e.mulMod(b.xx, x1, x1)
	e.mulMod(b.yy, y1, y1)
	e.mulMod(b.yyyy, b.yy, b.yy)
	b.t0.Add(x1, b.yy)
	e.mulMod(b.t0, b.t0, b.t0)
	b.t0.Sub(b.t0, b.xx)
	b.t0.Sub(b.t0, b.yyyy)
	b.s.Lsh(b.t0, 1)
	b.t0.Lsh(b.xx, 1).Add(b.t0, b.xx)
	b.m.Add(b.t0, e.a)
	e.mulMod(b.t0, b.m, b.m)
	b.t1.Lsh(b.s, 1)
	b.t.Sub(b.t0, b.t1)
	x.Set(b.t)
	b.t0.Sub(b.s, b.t)
	b.t1.Lsh(b.yyyy, 3)
	e.mulMod(b.t0, b.m, b.t0)
	y.Sub(b.t0, b.t1)
	z.Lsh(y1, 1)
	e.scale(b.t0, b.t1, x, y, z)
	return x, y
}

func (e *swEllipticCurve) ScalarMult(x1, y1 *big.Int, k []byte) (x, y *big.Int) {
	kk := new(big.Int).SetBytes(k)
	kk = new(big.Int).Mod(kk, e.params.N)

	x2, y2, z2 := big.NewInt(1), big.NewInt(1), big.NewInt(0)
	x3, y3, z3 := new(big.Int).Set(x1), new(big.Int).Set(y1), big.NewInt(1)

	b := newArithmeticBuffer()

	for i := kk.BitLen() - 1; i >= 0; i-- {
		if kk.Bit(i) == 0 {
			e.jacobianAdd(b, x3, y3, z3, x2, y2, z2)
			e.jacobianDouble(b, x2, y2, z2)
		} else {
			e.jacobianAdd(b, x2, y2, z2, x3, y3, z3)
			e.jacobianDouble(b, x3, y3, z3)
		}
	}

	e.scale(b.t0, b.t1, x2, y2, z2)
	return x2, y2
}

func (e *swEllipticCurve) ScalarBaseMult(k []byte) (x, y *big.Int) {
	return e.ScalarMult(e.params.Gx, e.params.Gy, k)
}

type arithmeticBuffer struct {
	t0, t1                                        *big.Int
	z1z1, z2z2, u1, u2, s1, s2, h, hh, i, j, r, v *big.Int
	xx, yy, yyyy, zz, s, m, t                     *big.Int
}

func newArithmeticBuffer() *arithmeticBuffer {
	t0 := new(big.Int)
	t1 := new(big.Int)
	xx := new(big.Int)
	yy := new(big.Int)
	yyyy := new(big.Int)
	zz := new(big.Int)
	s := new(big.Int)
	m := new(big.Int)
	t := new(big.Int)
	return &arithmeticBuffer{
		t0:   t0,
		t1:   t1,
		z1z1: new(big.Int),
		z2z2: new(big.Int),
		u1:   new(big.Int),
		u2:   new(big.Int),
		s1:   new(big.Int),
		s2:   xx,
		h:    yy,
		hh:   yyyy,
		i:    zz,
		j:    s,
		r:    m,
		v:    t,
		xx:   xx,
		yy:   yy,
		yyyy: yyyy,
		zz:   zz,
		s:    s,
		m:    m,
		t:    t,
	}
}

func (e *swEllipticCurve) jacobianAdd(b *arithmeticBuffer, x1, y1, z1, x2, y2, z2 *big.Int) {
	if z1.Cmp(zero) == 0 {
		x1.Set(x2)
		y1.Set(y2)
		z1.Set(z2)
		return
	}
	if z2.Cmp(zero) == 0 {
		return
	}
	if x1.Cmp(x2) == 0 && y1.Cmp(y2) == 0 {
		e.jacobianDouble(b, x1, y1, z1)
		return
	}

	e.mulMod(b.z1z1, z1, z1)
	e.mulMod(b.z2z2, z2, z2)
	e.mulMod(b.u1, x1, b.z2z2)
	e.mulMod(b.u2, x2, b.z1z1)
	e.mulMod(b.t0, z2, b.z2z2)
	e.mulMod(b.s1, y1, b.t0)
	e.mulMod(b.t0, z1, b.z1z1)
	e.mulMod(b.s2, y2, b.t0)
	b.h.Sub(b.u2, b.u1)
	b.t0.Lsh(b.h, 1)
	e.mulMod(b.i, b.t0, b.t0)
	e.mulMod(b.j, b.h, b.i)
	b.t0.Sub(b.s2, b.s1)
	b.r.Lsh(b.t0, 1)
	e.mulMod(b.v, b.u1, b.i)
	e.mulMod(b.t0, b.r, b.r)
	b.t1.Lsh(b.v, 1)
	b.t0.Sub(b.t0, b.j)
	x1.Sub(b.t0, b.t1)
	b.t0.Sub(b.v, x1)
	e.mulMod(b.t1, b.s1, b.j)
	b.t1.Lsh(b.t1, 1)
	e.mulMod(b.t0, b.r, b.t0)
	y1.Sub(b.t0, b.t1)
	b.t0.Add(z1, z2)
	e.mulMod(b.t0, b.t0, b.t0)
	b.t0.Sub(b.t0, b.z1z1)
	b.t0.Sub(b.t0, b.z2z2)
	e.mulMod(z1, b.t0, b.h)
}

func (e *swEllipticCurve) jacobianDouble(b *arithmeticBuffer, x1, y1, z1 *big.Int) {
	if z1.Cmp(zero) == 0 {
		return
	}

	e.mulMod(b.xx, x1, x1)
	e.mulMod(b.yy, y1, y1)
	e.mulMod(b.yyyy, b.yy, b.yy)
	e.mulMod(b.zz, z1, z1)
	b.t0.Add(x1, b.yy)
	e.mulMod(b.t0, b.t0, b.t0)
	b.t0.Sub(b.t0, b.xx)
	b.t0.Sub(b.t0, b.yyyy)
	b.s.Lsh(b.t0, 1)
	e.mulMod(b.t0, b.zz, b.zz)
	e.mulMod(b.t0, e.a, b.t0)
	b.t1.Lsh(b.xx, 1).Add(b.t1, b.xx)
	b.m.Add(b.t1, b.t0)
	e.mulMod(b.t0, b.m, b.m)
	b.t1.Lsh(b.s, 1)
	b.t.Sub(b.t0, b.t1)
	x1.Set(b.t)
	b.t0.Sub(b.s, b.t)
	b.t1.Lsh(b.yyyy, 3)
	e.mulMod(b.t0, b.m, b.t0)
	b.yyyy.Sub(b.t0, b.t1)
	b.t0.Add(y1, z1)
	y1.Set(b.yyyy)
	e.mulMod(b.t0, b.t0, b.t0)
	b.t0.Sub(b.t0, b.yy)
	z1.Sub(b.t0, b.zz)
}

// Converts Jacobian to Affine coordinates using two temporary values
func (e *swEllipticCurve) scale(t0, t1, x1, y1, z1 *big.Int) {
	if z1.Cmp(zero) == 0 {
		x1.Set(zero)
		y1.Set(zero)
		z1.Set(one)
	} else {
		a := t0.ModInverse(z1, e.params.P)
		aa := e.mulMod(t1, a, a)
		e.mulMod(x1, x1, aa)
		t0 = e.mulMod(t0, aa, a)
		e.mulMod(y1, y1, t0)
		z1.Set(one)
	}
}

func (e *swEllipticCurve) mulMod(dst, a, b *big.Int) *big.Int {
	return dst.Mul(a, b).Mod(dst, e.params.P)
}
