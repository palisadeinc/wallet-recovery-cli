package bits

import "math/bits"

// Carryless multiplication of two 64 bit values and returns the lowest 64 bits of the result
func bmul64(x, y uint64) uint64 {
	var x0, x1, x2, x3 uint64
	var y0, y1, y2, y3 uint64
	var z0, z1, z2, z3 uint64

	x0 = x & 0x1111111111111111
	x1 = x & 0x2222222222222222
	x2 = x & 0x4444444444444444
	x3 = x & 0x8888888888888888
	y0 = y & 0x1111111111111111
	y1 = y & 0x2222222222222222
	y2 = y & 0x4444444444444444
	y3 = y & 0x8888888888888888
	z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1)
	z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2)
	z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3)
	z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0)
	z0 &= 0x1111111111111111
	z1 &= 0x2222222222222222
	z2 &= 0x4444444444444444
	z3 &= 0x8888888888888888
	return z0 | z1 | z2 | z3
}

func genericGF2Mul128(x1, x0, y1, y0 uint64) [4]uint64 {
	var x0r, x1r, x2, x2r uint64
	var y0r, y1r, y2, y2r uint64
	var z0, z1, z2, z0h, z1h, z2h uint64

	x0r = bits.Reverse64(x0)
	x1r = bits.Reverse64(x1)
	x2 = x0 ^ x1
	x2r = x0r ^ x1r

	y0r = bits.Reverse64(y0)
	y1r = bits.Reverse64(y1)
	y2 = y0 ^ y1
	y2r = y0r ^ y1r

	z0 = bmul64(x0, y0)
	z1 = bmul64(x1, y1)
	z2 = bmul64(x2, y2)

	z0h = bmul64(x0r, y0r)
	z1h = bmul64(x1r, y1r)
	z2h = bmul64(x2r, y2r)

	z2 ^= z0 ^ z1
	z2h ^= z0h ^ z1h

	z0h = bits.Reverse64(z0h) >> 1
	z1h = bits.Reverse64(z1h) >> 1
	z2h = bits.Reverse64(z2h) >> 1

	var v [4]uint64
	v[0] = z0
	v[1] = z0h ^ z2
	v[2] = z1 ^ z2h
	v[3] = z1h

	return v
}
