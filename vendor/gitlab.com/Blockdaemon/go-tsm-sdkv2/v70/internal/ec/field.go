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
	fieldSecp256k1Zn    = 714
	fieldP224Zn         = 713
	fieldP256Zn         = 415
	fieldP384Zn         = 715
	fieldP521Zn         = 716
	fieldEdwards25519Zn = 949
	fieldEdwards448Zn   = 960
	fieldBLS12381Zn     = 3000
	fieldBLS12381GT     = 3001
	fieldStarkCurveZn   = 3010
	fieldPallasZn       = 3020
	fieldBabyJubjubZn   = 3040
	fieldEdwards377Zn   = 3050
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
		fieldEdwards25519ZnModulus := "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"
		fieldEdwards448ZnModulus := "3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7CCA23E9C44EDB49AED63690216CC2728DC58F552378C292AB5844F3"
		fieldBLS12381ZnModulus := "73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001"
		fieldStarkCurveZnModulus := "800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F"
		fieldPallasZnModulus := "40000000000000000000000000000000224698FC0994A8DD8C46EB2100000001"
		fieldBabyJubjubZnModulus := "60C89CE5C263405370A08B6D0302B0BAB3EEDB83920EE0A677297DC392126F1"
		fieldEdwards377ZnModulus := "04AAD957A68B2955982D1347970DEC005293A3AFC43C8AFEB95AEE9AC33FD9FF"

		fields[fieldSecp256k1Zn] = newSecp256k1ZnField()

		n, _ := new(big.Int).SetString(fieldP224ZnModulus, 16)
		fields[fieldP224Zn] = newGenericField(n, fieldP224Zn)

		n, _ = new(big.Int).SetString(fieldP256ZnModulus, 16)
		fields[fieldP256Zn] = newGenericField(n, fieldP256Zn)

		n, _ = new(big.Int).SetString(fieldP384ZnModulus, 16)
		fields[fieldP384Zn] = newGenericField(n, fieldP384Zn)

		n, _ = new(big.Int).SetString(fieldP521ZnModulus, 16)
		fields[fieldP521Zn] = newGenericField(n, fieldP521Zn)

		n, _ = new(big.Int).SetString(fieldEdwards25519ZnModulus, 16)
		fields[fieldEdwards25519Zn] = newGenericField(n, fieldEdwards25519Zn)

		n, _ = new(big.Int).SetString(fieldEdwards448ZnModulus, 16)
		fields[fieldEdwards448Zn] = newGenericField(n, fieldEdwards448Zn)

		n, _ = new(big.Int).SetString(fieldBLS12381ZnModulus, 16)
		fields[fieldBLS12381Zn] = newGenericField(n, fieldBLS12381Zn)

		fields[fieldBLS12381GT] = newBLS12381GTField()

		n, _ = new(big.Int).SetString(fieldStarkCurveZnModulus, 16)
		fields[fieldStarkCurveZn] = newGenericField(n, fieldStarkCurveZn)

		n, _ = new(big.Int).SetString(fieldPallasZnModulus, 16)
		fields[fieldPallasZn] = newGenericField(n, fieldPallasZn)

		n, _ = new(big.Int).SetString(fieldBabyJubjubZnModulus, 16)
		fields[fieldBabyJubjubZn] = newGenericField(n, fieldBabyJubjubZn)

		n, _ = new(big.Int).SetString(fieldEdwards377ZnModulus, 16)
		fields[fieldEdwards377Zn] = newGenericField(n, fieldEdwards377Zn)
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
