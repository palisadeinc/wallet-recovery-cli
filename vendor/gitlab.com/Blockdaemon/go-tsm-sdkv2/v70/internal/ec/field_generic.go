package ec

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"io"
	"math/big"
)

type genericField struct {
	zero    *big.Int
	one     *big.Int
	modulus *big.Int
	factor  *big.Int
	shift   uint
	id      uint16
}

func newGenericField(modulus *big.Int, id uint16) genericField {
	shift := uint(modulus.BitLen() * 2)
	factor := new(big.Int).Lsh(big.NewInt(1), shift)
	factor.Div(factor, modulus)

	return genericField{
		zero:    big.NewInt(0),
		one:     big.NewInt(1),
		modulus: modulus,
		shift:   shift,
		factor:  factor,
		id:      id,
	}
}

// Barretts reduction algorithm. Only works when 0 < a < modulus^2
func (f genericField) mod(a *big.Int) {
	var t big.Int

	t.Mul(a, f.factor)
	t.Rsh(&t, f.shift)
	t.Mul(&t, f.modulus)
	a.Sub(a, &t)
	if a.Cmp(f.modulus) >= 0 {
		a.Sub(a, f.modulus)
	}
}

func (f genericField) Zero() Scalar {
	return Scalar{
		field: f,
		value: f.zero,
	}
}

func (f genericField) One() Scalar {
	return Scalar{
		field: f,
		value: f.one,
	}
}

// Modulus returns a pointer to the big.Int value. Do not modify it!
func (f genericField) Modulus() *big.Int {
	return f.modulus
}

func (f genericField) Equals(o Field) bool {
	f2, ok := o.(genericField)
	if !ok {
		return false
	}
	if f.id != 0 {
		return f.id == f2.id
	} else {
		return f.modulus.Cmp(f2.modulus) == 0
	}
}

func (f genericField) ByteLen() int {
	return (f.modulus.BitLen() + 7) / 8
}

func (f genericField) DecodeScalar(b []byte) (Scalar, error) {
	a, err := f.scalarDecode(b)
	if err != nil {
		return Scalar{}, err
	}

	return Scalar{
		field: f,
		value: a,
	}, nil
}

func (f genericField) NewRandomScalar() Scalar {
	s := Scalar{
		field: f,
		value: new(big.Int),
	}
	f.scalarSetFromReader(s.value, random.Reader)
	return s
}

func (f genericField) NewScalarFromReader(reader io.Reader) Scalar {
	s := Scalar{
		field: f,
		value: new(big.Int),
	}
	f.scalarSetFromReader(s.value, reader)
	return s
}

func (f genericField) NewScalarWithModularReduction(value *big.Int) Scalar {
	s := Scalar{
		field: f,
		value: new(big.Int),
	}
	f.scalarSetWithModularReduction(s.value, value)
	return s
}

func (f genericField) NewScalarIntWithModularReduction(value int) Scalar {
	s := Scalar{
		field: f,
		value: new(big.Int),
	}
	f.scalarSetWithModularReduction(s.value, big.NewInt(int64(value)))
	return s
}

func toBigInt(a interface{}) *big.Int {
	aa, valid := a.(*big.Int)
	if !valid {
		panic("invalid internal scalar representation")
	}
	return aa
}

func (f genericField) fieldID() uint16 {
	return f.id
}

func (f genericField) scalarSetFromReader(a interface{}, reader io.Reader) {
	aa := toBigInt(a)
	random.SetBigIntFromReader(aa, reader, f.modulus)
}

func (f genericField) scalarSetWithModularReduction(a interface{}, value *big.Int) {
	aa := toBigInt(a)
	if value.Sign() >= 0 && value.Cmp(f.modulus) < 0 {
		aa.Set(value)
	} else {
		aa.Mod(value, f.modulus)
	}
}

func (f genericField) scalarEncodeBigInt(a interface{}) *big.Int {
	aa := toBigInt(a)

	var r big.Int
	r.Set(aa)
	return &r
}

func (f genericField) scalarEncode(a interface{}) []byte {
	aa := toBigInt(a)

	b := make([]byte, f.ByteLen())
	aa.FillBytes(b)
	return b
}

func (f genericField) scalarDecode(b []byte) (interface{}, error) {
	if len(b) != f.ByteLen() {
		return Scalar{}, fmt.Errorf("invalid scalar length")
	}
	var r big.Int
	r.SetBytes(b)
	if r.Cmp(f.modulus) >= 0 {
		return Scalar{}, fmt.Errorf("scalar larger than modulus")
	}
	return &r, nil
}

func (f genericField) scalarAdd(a, b interface{}) interface{} {
	aa := toBigInt(a)
	bb := toBigInt(b)

	var r big.Int
	r.Add(aa, bb)
	if r.Cmp(f.modulus) >= 0 {
		r.Sub(&r, f.modulus)
	}
	return &r
}

func (f genericField) scalarSub(a, b interface{}) interface{} {
	aa := toBigInt(a)
	bb := toBigInt(b)

	var r big.Int
	r.Sub(aa, bb)
	if r.Sign() < 0 {
		r.Add(&r, f.modulus)
	}
	return &r
}

func (f genericField) scalarNeg(a interface{}) interface{} {
	aa := toBigInt(a)

	var r big.Int
	r.Neg(aa)
	r.Add(&r, f.modulus)
	return &r
}

func (f genericField) scalarMul(a interface{}, b interface{}) interface{} {
	aa := toBigInt(a)
	bb := toBigInt(b)

	var r big.Int
	r.Mul(aa, bb)
	f.mod(&r)

	return &r
}

func (f genericField) scalarDiv(a interface{}, b interface{}) interface{} {
	aa := toBigInt(a)
	bb := toBigInt(b)

	var r big.Int
	r.ModInverse(bb, f.modulus)
	r.Mul(&r, aa)
	f.mod(&r)

	return &r
}

func (f genericField) scalarInv(a interface{}) interface{} {
	aa := toBigInt(a)

	var r big.Int
	if r.ModInverse(aa, f.modulus) == nil {
		panic("no modular inverse")
	}
	return &r
}

func (f genericField) scalarEquals(a, b interface{}) bool {
	aa := toBigInt(a)
	bb := toBigInt(b)

	return aa.Cmp(bb) == 0
}
