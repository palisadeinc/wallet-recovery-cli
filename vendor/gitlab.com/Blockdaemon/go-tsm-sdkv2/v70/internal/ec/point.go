package ec

import (
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"math/big"
)

// Point represents a point on an elliptic curve. The internal representation of an actual point is determined by the
// curve implementation.

type Point struct {
	curve     Curve
	basePoint bool
	value     interface{}
}

func (p Point) Curve() Curve {
	return p.curve
}

func (p Point) IsEmpty() bool {
	return p.curve == nil || p.value == nil
}

func (p Point) Encode() []byte {
	return p.curve.pointEncode(p.value, false)
}

func (p Point) EncodeCompressed() []byte {
	return p.curve.pointEncode(p.value, true)
}

func (p Point) Coordinates() (*big.Int, *big.Int, error) {
	return p.curve.pointCoordinates(p.value)
}

func (p Point) ECPublicKey() (*ecdsa.PublicKey, error) {
	_curve, ok := p.curve.(swCurve)
	if !ok {
		return nil, fmt.Errorf("EC public key is not supported for %s", p.curve.Name())
	}

	x, y, err := p.Coordinates()
	if err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: _curve.params.impl,
		X:     x,
		Y:     y,
	}, nil
}

func (p Point) Add(q Point) Point {
	if !p.curve.Equals(q.curve) {
		panic("points are from different elliptic curves")
	}
	value := p.curve.pointAdd(p.value, q.value)
	return Point{
		curve: p.curve,
		value: value,
	}
}

func (p Point) Subtract(q Point) Point {
	return p.Add(q.Negate())
}

func (p Point) Multiply(e Scalar) Point {
	value := p.curve.pointMultiply(p.value, e, p.basePoint, true)
	return Point{
		curve: p.curve,
		value: value,
	}
}

func (p Point) MultiplyVarTime(e Scalar) Point {
	value := p.curve.pointMultiply(p.value, e, p.basePoint, false)
	return Point{
		curve: p.curve,
		value: value,
	}
}

func (p Point) MultiplyByCofactor() Point {
	value := p.curve.pointMultiplyByCofactor(p.value)
	return Point{
		curve: p.curve,
		value: value,
	}
}

func (p Point) Negate() Point {
	value := p.curve.pointNegate(p.value)
	return Point{
		curve: p.curve,
		value: value,
	}
}

func (p Point) IsPointAtInfinity() bool {
	return p.curve.pointIsPointAtInfinity(p.value)
}

func (p Point) IsInLargeSubgroup() bool {
	return p.curve.pointIsInLargeSubgroup(p.value)
}

func (p Point) Equals(o Point) bool {
	return p.curve.Equals(o.curve) && p.curve.pointEquals(p.value, o.value)
}

func (p Point) MarshalBinary() ([]byte, error) {
	id := p.Curve().curveID()
	if _, exists := curves[id]; !exists {
		return nil, fmt.Errorf("no curve corresponds to ID: %d", id)
	}
	b := make([]byte, 2, 2+p.Curve().EncodedPointLength())
	binary.BigEndian.PutUint16(b, id)
	b = append(b, p.Encode()...)
	return b, nil
}

func (p *Point) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("invalid length")
	}
	id := binary.BigEndian.Uint16(data)
	curve, err := newCurveFromID(id)
	if err != nil {
		return err
	}
	q, err := curve.pointDecode(data[2:], false)
	if err != nil {
		return err
	}
	p.curve = curve
	p.value = q
	return nil
}
