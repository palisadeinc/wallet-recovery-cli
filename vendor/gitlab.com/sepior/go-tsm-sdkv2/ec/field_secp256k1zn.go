package ec

import (
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/random"
	"io"
	"math/big"
	"sync"
)

type secp256k1ZnField struct {
	zero       *secp256k1.ModNScalar
	one        *secp256k1.ModNScalar
	bufferPool *sync.Pool
}

func newSecp256k1ZnField() secp256k1ZnField {
	var zero, one secp256k1.ModNScalar

	zero.SetInt(0)
	one.SetInt(1)

	return secp256k1ZnField{
		zero: &zero,
		one:  &one,
		bufferPool: &sync.Pool{
			New: func() any {
				return &[32]byte{}
			},
		},
	}
}

func (f secp256k1ZnField) Zero() Scalar {
	return Scalar{
		field: f,
		value: f.zero,
	}
}

func (f secp256k1ZnField) One() Scalar {
	return Scalar{
		field: f,
		value: f.one,
	}
}

// Modulus returns a pointer to the big.Int value. Do not modify it!
func (f secp256k1ZnField) Modulus() *big.Int {
	return secp256k1.Params().N
}

func (f secp256k1ZnField) Equals(o Field) bool {
	_, ok := o.(secp256k1ZnField)
	return ok
}

func (f secp256k1ZnField) ByteLen() int {
	return 32
}

func (f secp256k1ZnField) DecodeScalar(b []byte) (Scalar, error) {
	a, err := f.scalarDecode(b)
	if err != nil {
		return Scalar{}, err
	}

	return Scalar{
		field: f,
		value: a,
	}, nil
}

func (f secp256k1ZnField) NewRandomScalar() Scalar {
	s := Scalar{
		field: f,
		value: &secp256k1.ModNScalar{},
	}
	f.scalarSetFromReader(s.value, random.Reader)
	return s
}

func (f secp256k1ZnField) NewScalarFromReader(reader io.Reader) Scalar {
	s := Scalar{
		field: f,
		value: &secp256k1.ModNScalar{},
	}
	f.scalarSetFromReader(s.value, reader)
	return s
}

func (f secp256k1ZnField) NewScalarWithModularReduction(value *big.Int) Scalar {
	s := Scalar{
		field: f,
		value: &secp256k1.ModNScalar{},
	}
	f.scalarSetWithModularReduction(s.value, value)
	return s
}

func (f secp256k1ZnField) NewScalarIntWithModularReduction(value int) Scalar {
	s := Scalar{
		field: f,
		value: &secp256k1.ModNScalar{},
	}
	f.scalarSetWithModularReduction(s.value, big.NewInt(int64(value)))
	return s
}

func toSecp256k1ZnScalar(a interface{}) *secp256k1.ModNScalar {
	aa, valid := a.(*secp256k1.ModNScalar)
	if !valid {
		panic("invalid internal scalar representation")
	}
	return aa
}

func (f secp256k1ZnField) fieldID() uint16 {
	return fieldSecp256k1Zn
}

func (f secp256k1ZnField) scalarSetFromReader(a interface{}, reader io.Reader) {
	aa := toSecp256k1ZnScalar(a)
	b := f.bufferPool.Get().(*[32]byte)
	for {
		_, err := io.ReadFull(reader, b[:])
		if err != nil {
			panic(err)
		}
		if aa.SetBytes(b) == 0 {
			break
		}
	}
	f.bufferPool.Put(b)
}

func (f secp256k1ZnField) scalarSetWithModularReduction(a interface{}, value *big.Int) {
	aa := toSecp256k1ZnScalar(a)
	if value.Sign() >= 0 && value.BitLen() <= 256 {
		aa.SetByteSlice(value.Bytes())
	} else {
		var r big.Int
		r.Mod(value, secp256k1.Params().N)
		aa.SetByteSlice(r.Bytes())
	}
}

func (f secp256k1ZnField) scalarEncodeBigInt(a interface{}) *big.Int {
	aa := toSecp256k1ZnScalar(a)

	var r big.Int
	b := aa.Bytes()
	r.SetBytes(b[:])
	return &r
}

func (f secp256k1ZnField) scalarEncode(a interface{}) []byte {
	aa := toSecp256k1ZnScalar(a)

	b := aa.Bytes()
	return b[:]
}

func (f secp256k1ZnField) scalarDecode(b []byte) (interface{}, error) {
	if len(b) != f.ByteLen() {
		return Scalar{}, fmt.Errorf("invalid scalar length")
	}

	var r secp256k1.ModNScalar
	if r.SetByteSlice(b) {
		return Scalar{}, fmt.Errorf("scalar larger than modulus")
	}
	return &r, nil
}

func (f secp256k1ZnField) scalarAdd(a, b interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)
	bb := toSecp256k1ZnScalar(b)

	var r secp256k1.ModNScalar
	r.Add2(aa, bb)

	return &r
}

func (f secp256k1ZnField) scalarSub(a, b interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)
	bb := toSecp256k1ZnScalar(b)

	var r secp256k1.ModNScalar
	r.NegateVal(bb)
	r.Add(aa)

	return &r
}

func (f secp256k1ZnField) scalarNeg(a interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)

	var r secp256k1.ModNScalar
	r.NegateVal(aa)

	return &r
}

func (f secp256k1ZnField) scalarMul(a interface{}, b interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)
	bb := toSecp256k1ZnScalar(b)

	var r secp256k1.ModNScalar
	r.Mul2(aa, bb)

	return &r
}

func (f secp256k1ZnField) scalarDiv(a interface{}, b interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)
	bb := toSecp256k1ZnScalar(b)

	var r secp256k1.ModNScalar
	r.InverseValNonConst(bb)
	r.Mul(aa)

	return &r
}

func (f secp256k1ZnField) scalarInv(a interface{}) interface{} {
	aa := toSecp256k1ZnScalar(a)
	if aa.IsZero() {
		panic("no modular inverse")
	}

	var r secp256k1.ModNScalar
	r.InverseValNonConst(aa)

	return &r
}

func (f secp256k1ZnField) scalarEquals(a, b interface{}) bool {
	aa := toSecp256k1ZnScalar(a)
	bb := toSecp256k1ZnScalar(b)

	return aa.Equals(bb)
}
