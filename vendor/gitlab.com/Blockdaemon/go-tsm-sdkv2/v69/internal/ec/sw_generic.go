//go:build !extlib

package ec

import (
	"math/big"
)

func (c swCurve) pointAdd(p, q interface{}) interface{} {
	pp := toBytes(p)
	qq := toBytes(q)
	x1, y1, _ := c.pointCoordinates(pp)
	x2, y2, _ := c.pointCoordinates(qq)

	x, y := c.params.impl.Add(x1, y1, x2, y2)
	return swXYToValue(x, y, c.params.pLen)
}

func (c swCurve) pointMultiplyImpl(p interface{}, e []byte, basePoint, constantTime bool) interface{} {
	var x, y *big.Int
	if basePoint {
		x, y = c.params.impl.ScalarBaseMult(e)
	} else {
		x1, y1, _ := c.pointCoordinates(p)
		x, y = c.params.impl.ScalarMult(x1, y1, e)
	}

	return swXYToValue(x, y, c.params.pLen)
}

func swXYToValue(x, y *big.Int, byteSize int) []byte {
	b := make([]byte, 2*byteSize)

	if x.BitLen() == 0 && y.BitLen() == 0 {
		return b
	}

	x.FillBytes(b[:byteSize])
	y.FillBytes(b[byteSize:])

	return b
}
