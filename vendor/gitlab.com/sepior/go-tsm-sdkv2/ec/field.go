package ec

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
)

const (
	fieldSecp256k1Zn = 714
	fieldP224Zn      = 713
	fieldP256Zn      = 415
	fieldP384Zn      = 715
	fieldP521Zn      = 716
	fieldEd25519Zn   = 949
	fieldEd448Zn     = 960
	fieldBLS12381Zn  = 3000
	fieldBLS12381GT  = 3001
)

var (
	fieldsInitialized sync.Once
	fields            = map[uint16]Field{}
)

type Field interface {
	Zero() Scalar
	One() Scalar
	Modulus() *big.Int
	Equals(o Field) bool
	ByteLen() int
	DecodeScalar(b []byte) (Scalar, error)

	NewRandomScalar() Scalar
	NewScalarFromReader(reader io.Reader) Scalar
	NewScalarWithModularReduction(value *big.Int) Scalar
	NewScalarIntWithModularReduction(value int) Scalar

	fieldID() uint16
	scalarSetFromReader(a interface{}, reader io.Reader)
	scalarSetWithModularReduction(a interface{}, value *big.Int)
	scalarEncodeBigInt(a interface{}) *big.Int
	scalarEncode(a interface{}) []byte
	scalarDecode(b []byte) (interface{}, error)
	scalarAdd(a, b interface{}) interface{}
	scalarSub(a, b interface{}) interface{}
	scalarNeg(a interface{}) interface{}
	scalarMul(a interface{}, b interface{}) interface{}
	scalarDiv(a interface{}, b interface{}) interface{}
	scalarInv(a interface{}) interface{}
	scalarEquals(a, b interface{}) bool
}

func init() {
	initFields()
}

func initFields() {
	fieldsInitialized.Do(func() {
		fieldP224ZnModulus := strings.ToUpper(elliptic.P224().Params().N.Text(16))
		fieldP256ZnModulus := strings.ToUpper(elliptic.P256().Params().N.Text(16))
		fieldP384ZnModulus := strings.ToUpper(elliptic.P384().Params().N.Text(16))
		fieldP521ZnModulus := strings.ToUpper(elliptic.P521().Params().N.Text(16))
		fieldEd25519ZnModulus := "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"
		fieldEd448ZnModulus := "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"
		fieldBLS12381ZnModulus := "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001"

		fields[fieldSecp256k1Zn] = newSecp256k1ZnField()

		n, _ := new(big.Int).SetString(fieldP224ZnModulus, 16)
		fields[fieldP224Zn] = newGenericField(n, fieldP224Zn)

		n, _ = new(big.Int).SetString(fieldP256ZnModulus, 16)
		fields[fieldP256Zn] = newGenericField(n, fieldP256Zn)

		n, _ = new(big.Int).SetString(fieldP384ZnModulus, 16)
		fields[fieldP384Zn] = newGenericField(n, fieldP384Zn)

		n, _ = new(big.Int).SetString(fieldP521ZnModulus, 16)
		fields[fieldP521Zn] = newGenericField(n, fieldP521Zn)

		n, _ = new(big.Int).SetString(fieldEd25519ZnModulus, 16)
		fields[fieldEd25519Zn] = newGenericField(n, fieldEd25519Zn)

		n, _ = new(big.Int).SetString(fieldEd448ZnModulus, 16)
		fields[fieldEd448Zn] = newGenericField(n, fieldEd448Zn)

		n, _ = new(big.Int).SetString(fieldBLS12381ZnModulus, 16)
		fields[fieldBLS12381Zn] = newGenericField(n, fieldBLS12381Zn)

		fields[fieldBLS12381GT] = newBLS12381GTField()
	})
}

func NewField(modulus *big.Int) (Field, error) {
	if modulus.Sign() <= 0 {
		return nil, errors.New("modulus cannot be negative or zero")
	}
	for _, f := range fields {
		if f.Modulus().Cmp(modulus) == 0 {
			return f, nil
		}
	}
	return newGenericField(modulus, 0), nil
}

func NewFieldInt(modulus int) (Field, error) {
	return NewField(big.NewInt(int64(modulus)))
}

func newFieldFromID(id uint16) (Field, error) {
	field, exists := fields[id]
	if !exists {
		return nil, fmt.Errorf("no field corresponds to ID: %d", id)
	}
	return field, nil
}

func ReverseSlice(b []byte) {
	l := len(b)
	for i := 0; i < l/2; i++ {
		tt := b[i]
		b[i] = b[l-1-i]
		b[l-1-i] = tt
	}
}
