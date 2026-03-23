package ec

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
)

type Scalar struct {
	field Field
	value interface{}
}

func (e Scalar) Field() Field {
	return e.field
}

func (e Scalar) IsEmpty() bool {
	return e.field == nil || e.value == nil
}

func (e Scalar) Value() *big.Int {
	return e.field.scalarEncodeBigInt(e.value)
}

func (e Scalar) Encode() []byte {
	return e.field.scalarEncode(e.value)
}

func (e Scalar) SetRandom() {
	e.field.scalarSetFromReader(e.value, random.Reader)
}

func (e Scalar) SetFromReader(r io.Reader) {
	e.field.scalarSetFromReader(e.value, r)
}

func (e Scalar) SetWithModularReduction(v *big.Int) {
	e.field.scalarSetWithModularReduction(e.value, v)
}

func (e Scalar) SetIntWithModularReduction(v int) {
	e.field.scalarSetWithModularReduction(e.value, big.NewInt(int64(v)))
}

func (e Scalar) Add(a Scalar) Scalar {
	if !e.field.Equals(a.field) {
		panic("cannot add elements from different fields")
	}
	value := e.field.scalarAdd(e.value, a.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Subtract(a Scalar) Scalar {
	if !e.field.Equals(a.field) {
		panic("cannot subtract elements from different fields")
	}
	value := e.field.scalarSub(e.value, a.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Negate() Scalar {
	value := e.field.scalarNeg(e.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Multiply(a Scalar) Scalar {
	if !e.field.Equals(a.field) {
		panic("cannot multiply elements from different fields")
	}
	value := e.field.scalarMul(e.value, a.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Divide(a Scalar) Scalar {
	if !e.field.Equals(a.field) {
		panic("cannot divide elements from different fields")
	}
	value := e.field.scalarDiv(e.value, a.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Invert() Scalar {
	value := e.field.scalarInv(e.value)
	return Scalar{
		field: e.field,
		value: value,
	}
}

func (e Scalar) Equals(o Scalar) bool {
	return e.field.Equals(o.field) && e.field.scalarEquals(e.value, o.value)
}

func (e Scalar) MarshalBinary() ([]byte, error) {
	id := e.Field().fieldID()
	if _, exists := fields[id]; !exists {
		return nil, fmt.Errorf("no field corresponds to ID: %d", id)
	}
	b := make([]byte, 2, 2+e.Field().ByteLen())
	binary.BigEndian.PutUint16(b, id)
	b = append(b, e.Encode()...)
	return b, nil
}

func (e *Scalar) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("invalid length")
	}
	id := binary.BigEndian.Uint16(data)
	field, err := newFieldFromID(id)
	if err != nil {
		return err
	}
	s, err := field.scalarDecode(data[2:])
	if err != nil {
		return err
	}
	e.field = field
	e.value = s
	return nil
}
