package ec

import (
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"io"
	"math/big"
)

type bls12381GTField struct {
	zero *bls12381.E12
	one  *bls12381.E12
}

func newBLS12381GTField() bls12381GTField {
	var zero, one bls12381.E12
	one.SetOne()
	zero.SetOne()
	zero.Sub(&zero, &one)

	return bls12381GTField{
		zero: &zero,
		one:  &one,
	}
}

func (f bls12381GTField) Zero() Scalar {
	return Scalar{
		field: f,
		value: f.zero,
	}
}

func (f bls12381GTField) One() Scalar {
	return Scalar{
		field: f,
		value: f.one,
	}
}

func (f bls12381GTField) Modulus() *big.Int {
	return big.NewInt(0)
}

func (f bls12381GTField) Equals(o Field) bool {
	_, ok := o.(bls12381GTField)
	return ok
}

func (f bls12381GTField) ByteLen() int {
	return bls12381.SizeOfGT
}

func (f bls12381GTField) DecodeScalar(b []byte) (Scalar, error) {
	a, err := f.scalarDecode(b)
	if err != nil {
		return Scalar{}, err
	}

	return Scalar{
		field: f,
		value: a,
	}, nil
}

func (f bls12381GTField) NewRandomScalar() Scalar {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) NewScalarFromReader(reader io.Reader) Scalar {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) NewScalarWithModularReduction(value *big.Int) Scalar {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) NewScalarIntWithModularReduction(value int) Scalar {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func toBLS12381GT(a interface{}) *bls12381.E12 {
	aa, valid := a.(*bls12381.E12)
	if !valid {
		panic("invalid internal scalar representation")
	}
	return aa
}

func (f bls12381GTField) fieldID() uint16 {
	return fieldBLS12381GT
}

func (f bls12381GTField) scalarSetFromReader(a interface{}, reader io.Reader) {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) scalarSetWithModularReduction(a interface{}, value *big.Int) {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) scalarEncodeBigInt(a interface{}) *big.Int {
	panic(fmt.Errorf("not supported for BLS-12-381 GT"))
}

func (f bls12381GTField) scalarEncode(a interface{}) []byte {
	b := toBLS12381GT(a).Bytes()
	return b[:]
}

func (f bls12381GTField) scalarDecode(b []byte) (interface{}, error) {
	if len(b) != f.ByteLen() {
		return Scalar{}, fmt.Errorf("invalid scalar length")
	}
	var r bls12381.E12
	if err := r.SetBytes(b); err != nil {
		return nil, fmt.Errorf("invalid scalar encoding")
	}
	return &r, nil
}

func (f bls12381GTField) scalarAdd(a, b interface{}) interface{} {
	aa := toBLS12381GT(a)
	bb := toBLS12381GT(b)

	var r bls12381.E12
	r.Add(aa, bb)
	return &r
}

func (f bls12381GTField) scalarSub(a, b interface{}) interface{} {
	aa := toBLS12381GT(a)
	bb := toBLS12381GT(b)

	var r bls12381.E12
	r.Sub(aa, bb)
	return &r

}

func (f bls12381GTField) scalarNeg(a interface{}) interface{} {
	aa := toBLS12381GT(a)

	var r bls12381.E12
	r.Sub(f.zero, aa)
	return &r
}

func (f bls12381GTField) scalarMul(a interface{}, b interface{}) interface{} {
	aa := toBLS12381GT(a)
	bb := toBLS12381GT(b)

	var r bls12381.E12
	r.Mul(aa, bb)
	return &r
}

func (f bls12381GTField) scalarDiv(a interface{}, b interface{}) interface{} {
	aa := toBLS12381GT(a)
	bb := toBLS12381GT(b)

	var r bls12381.E12
	r.Div(aa, bb)
	return &r
}

func (f bls12381GTField) scalarInv(a interface{}) interface{} {
	aa := toBLS12381GT(a)
	if aa.IsZero() {
		panic("no modular inverse")
	}

	var r bls12381.E12
	r.Inverse(aa)
	return &r
}

func (f bls12381GTField) scalarEquals(a, b interface{}) bool {
	aa := toBLS12381GT(a)
	bb := toBLS12381GT(b)

	return aa.Equal(bb)
}
