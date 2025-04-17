package math

// This file contains a generic interface to operations on elliptic curves as well as operations on scalars of Zn.

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
)

var initonce sync.Once

func initAll() {
	initS256()
	initEdwards25519()
}

type Curve struct {
	name string
	impl elliptic.Curve
}

type Point struct {
	curve Curve
	x     *big.Int
	y     *big.Int
}

type Scalar struct {
	curve Curve
	k     *big.Int
}

func NewCurve(curveName string) (Curve, error) {
	var impl elliptic.Curve
	switch curveName {
	case "P-224":
		impl = elliptic.P224()
	case "P-256":
		impl = elliptic.P256()
	case "P-384":
		impl = elliptic.P384()
	case "P-521":
		impl = elliptic.P521()
	case "secp256k1":
		impl = S256()
	case "ED-25519":
		impl = Edwards25519()
	default:
		return Curve{}, fmt.Errorf("unsupported elliptic curve: %s", curveName)
	}
	if curveName != impl.Params().Name {
		panic("curve name mismatch")
	}
	return Curve{
		impl: impl,
		name: impl.Params().Name,
	}, nil
}

func (c Curve) Name() string {
	return c.name
}

func (c Curve) Impl() elliptic.Curve {
	return c.impl
}

func (c Curve) NewRandomScalar() Scalar {
	n, err := rand.Int(rand.Reader, c.impl.Params().N)
	if err != nil {
		panic(err)
	}

	return Scalar{
		curve: c,
		k:     n,
	}
}

func (c Curve) NewScalarInt(k int) Scalar {
	return c.NewScalarBigInt(big.NewInt(int64(k)))
}

func (c Curve) NewScalarBigInt(k *big.Int) Scalar {
	kk := new(big.Int).Set(k)
	kk.Mod(kk, c.impl.Params().N)

	return Scalar{
		curve: c,
		k:     kk,
	}
}

func (c Curve) NewScalarBytes(k []byte) Scalar {
	kk := new(big.Int).SetBytes(k)

	return c.NewScalarBigInt(kk)
}

func (c Curve) NewPoint(x, y *big.Int) (Point, error) {
	x1 := new(big.Int).Mod(x, c.impl.Params().P)
	y1 := new(big.Int).Mod(y, c.impl.Params().P)

	if !c.impl.IsOnCurve(x, y) {
		return Point{}, fmt.Errorf("coordinates are not on the curve")
	}

	return Point{
		curve: c,
		x:     x1,
		y:     y1,
	}, nil
}

func (c Curve) G() Point {
	x1 := new(big.Int).Set(c.impl.Params().Gx)
	y1 := new(big.Int).Set(c.impl.Params().Gy)

	return Point{
		curve: c,
		x:     x1,
		y:     y1,
	}
}

func (c Curve) O() Point {
	var y big.Int
	if c.impl.Params().Name == "ED-25519" {
		y.SetInt64(1)
	} else {
		y.SetInt64(0)
	}

	return Point{
		curve: c,
		x:     big.NewInt(0),
		y:     &y,
	}
}

func (c Curve) DecodePoint(b []byte) (Point, error) {
	var x, y *big.Int
	var err error

	if c.impl.Params().Name == "ED-25519" {
		x, y, err = decodeEdwards25519(b)
	} else {
		x, y, err = decodeElliptic(b, c.impl)
	}
	if err != nil {
		return Point{}, err
	}

	return Point{
		curve: c,
		x:     x,
		y:     y,
	}, nil
}

func (p Point) Encode() []byte {
	if p.curve.impl.Params().Name == "ED-25519" {
		return encodeEdwards25519(p.x, p.y)
	} else {
		return encodeElliptic(p.x, p.y, p.curve.impl)
	}
}

func (p Point) Coordinates() (*big.Int, *big.Int) {
	x := new(big.Int).Set(p.x)
	y := new(big.Int).Set(p.y)
	return x, y
}

func (p Point) Add(q Point) Point {
	var x, y *big.Int
	if p.Equals(q) {
		x, y = p.curve.impl.Double(p.x, p.y)
	} else {
		x, y = p.curve.impl.Add(p.x, p.y, q.x, q.y)
	}
	return Point{
		curve: p.curve,
		x:     x,
		y:     y,
	}
}

func (p Point) Sub(q Point) Point {
	return p.Add(q.Neg())
}

func (p Point) Neg() Point {
	var x, y big.Int
	if p.curve.impl.Params().Name == "ED-25519" {
		x.Neg(p.x)
		x.Mod(&x, p.curve.impl.Params().P)
		y.Set(p.y)
	} else {
		x.Set(p.x)
		y.Neg(p.y)
		y.Mod(&y, p.curve.impl.Params().P)
	}
	return Point{
		curve: p.curve,
		x:     &x,
		y:     &y,
	}
}

func (p Point) Mul(k Scalar) Point {
	x, y := p.curve.impl.ScalarMult(p.x, p.y, k.Value().Bytes())
	return Point{
		curve: p.curve,
		x:     x,
		y:     y,
	}
}

func (p Point) Curve() Curve {
	return p.curve
}

func (p Point) Equals(q Point) bool {
	if p.curve.impl.Params().Name != q.curve.impl.Params().Name {
		return false
	}
	if p.x.Cmp(q.x) != 0 || p.y.Cmp(q.y) != 0 {
		return false
	}
	return true
}

func (s Scalar) Encode() []byte {
	byteLen := (s.curve.impl.Params().N.BitLen() + 7) / 8

	b := make([]byte, byteLen)
	s.k.FillBytes(b)
	return b
}

func (s Scalar) Add(k Scalar) Scalar {
	r := new(big.Int).Add(s.k, k.k)

	return Scalar{
		curve: s.curve,
		k:     r.Mod(r, s.curve.impl.Params().N),
	}
}

func (s Scalar) Sub(k Scalar) Scalar {
	r := new(big.Int).Sub(s.k, k.k)

	return Scalar{
		curve: s.curve,
		k:     r.Mod(r, s.curve.impl.Params().N),
	}
}

func (s Scalar) Mul(k Scalar) Scalar {
	r := new(big.Int).Mul(s.k, k.k)

	return Scalar{
		curve: s.curve,
		k:     r.Mod(r, s.curve.impl.Params().N),
	}
}

func (s Scalar) Inv() Scalar {
	r := new(big.Int).ModInverse(s.k, s.curve.impl.Params().N)

	return Scalar{
		curve: s.curve,
		k:     r,
	}
}

func (s Scalar) Curve() Curve {
	return s.curve
}

func (s Scalar) Value() *big.Int {
	return s.k
}

func (s Scalar) Equals(k Scalar) bool {
	if s.Curve().impl.Params().Name != k.curve.impl.Params().Name || s.k.Cmp(k.k) != 0 {
		return false
	}
	return true
}
