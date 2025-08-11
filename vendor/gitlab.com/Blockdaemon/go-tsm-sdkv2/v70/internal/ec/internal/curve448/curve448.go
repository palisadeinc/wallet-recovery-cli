// Constant time implementation of the Curve448-Goldilocks elliptic curve.
//
// Curve448-Goldilocks is an Edwards curve with equation: y^2 + x^2 = 1 − 39081*x^2*y^2
//
// The Montgomery Ladder for scalar multiplication is not optimized. For better performance
// we could use the C reference implementation from https://sourceforge.net/p/ed448goldilocks

package curve448

import (
	"crypto/subtle"
)

type FieldElement [14]uint32

var fe0 FieldElement = [14]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}                                                                                                                               // 0
var fe1 FieldElement = [14]uint32{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}                                                                                                                               // 1
var feD FieldElement = [14]uint32{4294928214, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967294, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295} // -39081
var feGx FieldElement = [14]uint32{3339501662, 640067627, 2332070798, 1127973089, 716596497, 313400055, 2748556388, 3933070116, 1192171367, 2652136816, 582956762, 572331430, 1810697709, 1327067334}
var feGy FieldElement = [14]uint32{4063296020, 2550692187, 1322764461, 4257026860, 3866900932, 986971932, 94421719, 2272828446, 1822660672, 1273656179, 1456064354, 2289442871, 1857469476, 1765754481}

// Set R = 0
func feZero(r *FieldElement) {
	copy(r[:], fe0[:])
}

// Set R = 1
func feOne(r *FieldElement) {
	copy(r[:], fe1[:])
}

// Sets R = A
func feCopy(r, a *FieldElement) {
	copy(r[:], a[:])
}

// Returns 1 if A == B and 0 otherwise
func feEqual(a, b *FieldElement) int {
	var v uint32
	for i := 0; i < 14; i++ {
		v = v | a[i] ^ b[i]
	}
	return subtle.ConstantTimeEq(int32(v), 0)
}

// Decodes src as a little endian byte array and stores the result in dst
func feFromBytes(dst *FieldElement, src *[56]byte) {
	for i := 0; i < 14; i++ {
		s := src[i*4 : (i+1)*4]
		dst[i] = uint32(s[0])
		dst[i] = dst[i] | (uint32(s[1]) << 8)
		dst[i] = dst[i] | (uint32(s[2]) << 16)
		dst[i] = dst[i] | (uint32(s[3]) << 24)
	}
}

// Encodes src as a little endian byte array and stores the result in dst
func feToBytes(dst *[56]byte, src *FieldElement) {
	for i := 0; i < 14; i++ {
		idx := i * 4
		dst[idx+0] = byte(src[i] & 0xFF)
		dst[idx+1] = byte((src[i] >> 8) & 0xFF)
		dst[idx+2] = byte((src[i] >> 16) & 0xFF)
		dst[idx+3] = byte((src[i] >> 24) & 0xFF)
	}
}

// Computes R = A + B
func feAdd(r, a, b *FieldElement) {
	var t uint64 = 0
	for i := 0; i < 14; i++ {
		t = t + uint64(a[i])
		t = t + uint64(b[i])
		r[i] = uint32(t)
		t = t >> 32
	}

	feMod(r, r, uint32(t))
}

// Computes R = A - B
func feSubtract(r, a, b *FieldElement) {
	var t int64 = -1

	// R = A + P - B
	for i := 0; i < 14; i++ {
		if i == 7 {
			t = t - 1
		}
		t = t + int64(a[i])
		t = t - int64(b[i])
		r[i] = uint32(t)
		t = t >> 32
	}

	feMod(r, r, uint32(t+1))
}

// Computes R = A * B
func feMultiply(r, a, b *FieldElement) {
	var c uint64 = 0
	var t uint64 = 0
	var u [28]uint32

	// This uses Comba multiplication which computes the products column by column. This might not be the fastest
	// way of doing this, but it is easier to implement and has a low memory overhead.
	for i := 0; i < 28; i++ {
		if i < 14 {
			for j := 0; j <= i; j++ {
				t = t + uint64(a[j])*uint64(b[i-j])
				c = c + t>>32
				t = t & 0xFFFFFFFF
			}
		} else {
			for j := i - 13; j < 14; j++ {
				t = t + uint64(a[j])*uint64(b[i-j])
				c = c + t>>32
				t = t & 0xFFFFFFFF
			}
		}

		// Write the result at the bottom of each column
		u[i] = uint32(t)

		// Carry propagation
		t = c & 0xFFFFFFFF
		c = c >> 32
	}

	// First pass of fast modular reduction
	t = 0
	for i := 0; i < 14; i++ {
		t = t + uint64(u[i])
		t = t + uint64(u[i+14])
		if i < 7 {
			t = t + uint64(u[i+21])
		} else {
			t = t + uint64(u[i+7])
			t = t + uint64(u[i+14])
		}
		u[i] = uint32(t)
		t = t >> 32
	}

	// Second pass of fast modular reduction
	c = t
	for i := 0; i < 14; i++ {
		if i == 7 {
			t = t + c
		}
		t = t + uint64(u[i])
		u[i] = uint32(t)
		t = t >> 32
	}

	copy(r[:], u[:14])
	feMod(r, r, uint32(t))
}

// Sets R to the modular inverse of A
func feInvert(r, a *FieldElement) {
	u := &FieldElement{}
	v := &FieldElement{}

	// Find the multiplicative inverse of A mod P, where = 2^448 - 2^224 - 1, using Fermats little theorem
	feSquare(u, a)
	feMultiply(u, u, a)
	feSquare(u, u)
	feMultiply(v, u, a)
	fePow2x(u, v, 3)
	feMultiply(v, u, v)
	fePow2x(u, v, 6)
	feMultiply(u, u, v)
	feSquare(u, u)
	feMultiply(v, u, a)
	fePow2x(u, v, 13)
	feMultiply(u, u, v)
	feSquare(u, u)
	feMultiply(v, u, a)
	fePow2x(u, v, 27)
	feMultiply(u, u, v)
	feSquare(u, u)
	feMultiply(v, u, a)
	fePow2x(u, v, 55)
	feMultiply(u, u, v)
	feSquare(u, u)
	feMultiply(v, u, a)
	fePow2x(u, v, 111)
	feMultiply(v, u, v)
	feSquare(u, v)
	feMultiply(u, u, a)
	fePow2x(u, u, 223)
	feMultiply(u, u, v)
	feSquare(u, u)
	feSquare(u, u)
	feMultiply(r, u, a)
}

// Computes R = A^2 using feMultiply
func feSquare(r, a *FieldElement) {
	feMultiply(r, a, a)
}

// Computes R = A ^ (2^x)
func fePow2x(r, a *FieldElement, x int) {
	feSquare(r, a)
	for i := 1; i < x; i++ {
		feSquare(r, r)
	}
}

// Computes R = A mod P where 0 <= A < 2P
func feMod(r, a *FieldElement, h uint32) {
	var b FieldElement

	// B = A - P
	var t uint64 = 1
	for i := 0; i < 14; i++ {
		if i == 7 {
			t = t + 1
		}
		t = t + uint64(a[i])
		b[i] = uint32(t)
		t = t >> 32
	}
	h = h - 1 + uint32(t)

	// Select either the reduced output or the original value in constant time
	var mask = h&1 - 1
	for i := 0; i < 14; i++ {
		r[i] = (b[i] & mask) | (a[i] & ^mask)
	}
}

type ProjectiveGroupElement struct {
	x, y, z FieldElement
}

type AffineGroupElement struct {
	x, y FieldElement
}

// GeFromBytes decodes src per RFC 8032. Sets dst to the decoded point and returns true if decoding was successful.
// If decoding fails dst is undefined and the function returns false.
func GeFromBytes(dst *ProjectiveGroupElement, src *[57]byte) bool {
	// Check that the most significant byte is well-formed and get the sign of the x coordinate
	msb := src[56]
	x0 := (msb & 128) >> 7
	msb = msb & 127
	if msb != 0 {
		return false
	}

	// Initialise output
	x := &dst.x
	y := &dst.y
	feCopy(&dst.z, &fe1)

	// Get the y coordinate
	var yBuffer [56]byte
	copy(yBuffer[:], src[0:56])
	feFromBytes(y, &yBuffer)

	// U = Y^2 - 1 and V = D Y^2 - 1
	u := &FieldElement{}
	v := &FieldElement{}
	feSquare(u, y)
	feCopy(v, u)
	feSubtract(u, u, &fe1)
	feMultiply(v, v, &feD)
	feSubtract(v, v, &fe1)

	// U3 = U^3
	u3 := &FieldElement{}
	feSquare(u3, u)
	feMultiply(u3, u3, u)

	// C = U^5 * V^3
	c := &FieldElement{}
	feSquare(c, v)
	feMultiply(c, c, v)
	feMultiply(c, c, u3)
	feMultiply(c, c, u)
	feMultiply(c, c, u)

	// Compute X = U^3 * V * (U^5*V^3)^((P - 3)/4) = U3 * V * C^((P - 3)/4)
	// We use the fact that (P - 3)/4 = 2^446 - 2^222 - 1

	// X = C^((p - 3) / 4)
	d := &FieldElement{}
	feSquare(x, c)
	feMultiply(x, x, c)
	feSquare(x, x)
	feMultiply(d, x, c)
	fePow2x(x, d, 3)
	feMultiply(d, x, d)
	fePow2x(x, d, 6)
	feMultiply(x, x, d)
	feSquare(x, x)
	feMultiply(d, x, c)
	fePow2x(x, d, 13)
	feMultiply(x, x, d)
	feSquare(x, x)
	feMultiply(d, x, c)
	fePow2x(x, d, 27)
	feMultiply(x, x, d)
	feSquare(x, x)
	feMultiply(d, x, c)
	fePow2x(x, d, 55)
	feMultiply(x, x, d)
	feSquare(x, x)
	feMultiply(d, x, c)
	fePow2x(x, d, 111)
	feMultiply(d, x, d)
	feSquare(x, d)
	feMultiply(x, x, c)
	fePow2x(x, x, 223)
	feMultiply(x, x, d)

	// Compute the candidate square root X = U3 * V * C^((P - 3)/4)
	feMultiply(x, x, v)
	feMultiply(x, x, u3)

	// Check if U = V * X^2
	feSquare(c, x)
	feMultiply(c, c, v)
	if feEqual(c, u) == 0 {
		return false
	}

	if feEqual(x, &fe0) == 1 && x0 == 1 {
		return false
	}

	// If x0 != x mod 2 flip the x coordinate
	if x0 != byte(x[0]&1) {
		feSubtract(x, &fe0, x)
	}

	return true
}

// GeToBytes sets dst to the RFC 8032 encoding of src
func GeToBytes(dst *[57]byte, src *ProjectiveGroupElement) {
	q := &AffineGroupElement{}
	GeToAffine(q, src)
	var a [56]byte
	feToBytes(&a, &q.y)
	copy(dst[:], a[:])
	sign := byte(q.x[0]&1) << 7
	dst[56] = sign
}

// GeZero returns the point at infinity
func GeZero(p *ProjectiveGroupElement) {
	feZero(&p.x)
	feOne(&p.y)
	feOne(&p.z)
}

// GeGenerator returns the standard generator
func GeGenerator(p *ProjectiveGroupElement) {
	feCopy(&p.x, &feGx)
	feCopy(&p.y, &feGy)
	feOne(&p.z)
}

// GeCopy sets P = Q
func GeCopy(p, q *ProjectiveGroupElement) {
	feCopy(&p.x, &q.x)
	feCopy(&p.y, &q.y)
	feCopy(&p.z, &q.z)
}

// GeIsZero returns 1 if P is the point at infinity and 0 otherwise
func GeIsZero(p *ProjectiveGroupElement) int {
	return feEqual(&p.x, &fe0)
}

// GeAdd computes R = P + Q
func GeAdd(r, p, q *ProjectiveGroupElement) {
	x1 := p.x
	y1 := p.y
	z1 := p.z

	x2 := q.x
	y2 := q.y
	z2 := q.z

	a := &FieldElement{}
	b := &FieldElement{}
	c := &FieldElement{}
	d := &FieldElement{}
	e := &FieldElement{}
	f := &FieldElement{}
	g := &FieldElement{}
	h := &FieldElement{}

	// A = Z1*Z2
	feMultiply(a, &z1, &z2)

	// B = A^2
	feSquare(b, a)

	// C = X1*X2
	feMultiply(c, &x1, &x2)

	// D = Y1*Y2
	feMultiply(d, &y1, &y2)

	// E = d*C*D
	feMultiply(e, c, d)
	feMultiply(e, e, &feD)

	// F = B-E
	feSubtract(f, b, e)

	// G = B+E
	feAdd(g, b, e)

	// H = (X1+Y1)*(X2+Y2)
	feAdd(b, &x1, &y1)
	feAdd(h, &x2, &y2)
	feMultiply(h, b, h)

	// X3 = A*F*(H-C-D)
	feSubtract(&r.x, h, c)
	feSubtract(&r.x, &r.x, d)
	feMultiply(&r.x, &r.x, f)
	feMultiply(&r.x, &r.x, a)

	// Y3 = A*G*(D-C)
	feSubtract(&r.y, d, c)
	feMultiply(&r.y, &r.y, g)
	feMultiply(&r.y, &r.y, a)

	// Z3 = F*G
	feMultiply(&r.z, f, g)
}

// GeNeg computes R = -P
func GeNeg(r, p *ProjectiveGroupElement) {
	feSubtract(&r.x, &fe0, &p.x)
	feCopy(&r.y, &p.y)
	feCopy(&r.z, &p.z)
}

// GeDbl computes R = 2*P
func GeDbl(r, p *ProjectiveGroupElement) {
	x1 := p.x
	y1 := p.y
	z1 := p.z

	b := &FieldElement{}
	c := &FieldElement{}
	d := &FieldElement{}
	e := &FieldElement{}
	h := &FieldElement{}
	j := &FieldElement{}

	// B = (X1+Y1)^2
	feAdd(b, &x1, &y1)
	feSquare(b, b)

	// C = X1^2
	feSquare(c, &x1)

	// D = Y1^2
	feSquare(d, &y1)

	// E = C+D
	feAdd(e, c, d)

	// H = Z1^2
	feSquare(h, &z1)

	// J = E-2*H
	feAdd(j, h, h)
	feSubtract(j, e, j)

	// X3 = (B-E)*J
	feSubtract(&r.x, b, e)
	feMultiply(&r.x, &r.x, j)

	// Y3 = E*(C-D)
	feSubtract(&r.y, c, d)
	feMultiply(&r.y, e, &r.y)

	// Z3 = E*J
	feMultiply(&r.z, e, j)
}

// GeMul computes R = s*P in constant time
func GeMul(r, p *ProjectiveGroupElement, s [56]byte) {
	r1 := &ProjectiveGroupElement{}
	GeZero(r)
	GeCopy(r1, p)

	for i := 446 - 1; i >= 0; i-- {
		byteIndex := i / 8
		bitInByteIndex := i % 8
		mask := (byte)(1 << bitInByteIndex)
		isSet := (s[byteIndex] & mask) != 0
		if isSet {
			GeAdd(r, r, r1)
			GeDbl(r1, r1)
		} else {
			GeAdd(r1, r, r1)
			GeDbl(r, r)
		}
	}
}

// GeMulVarTime computes R = s*P as fast as possible
func GeMulVarTime(r, p *ProjectiveGroupElement, s [56]byte) {
	GeZero(r)

	// Find the most significant non-zero bit
	startIndex := 0
	for i := 55; i >= 0; i-- {
		b := s[i]
		if b != 0 {
			startIndex = (i+1)*8 - 1
			for j := 7; j >= 0; j-- {
				mask := (byte)(1 << j)
				if (b & mask) != 0 {
					break
				}
				startIndex = startIndex - 1
			}
			break
		}
	}

	for i := startIndex; i >= 0; i-- {
		byteIndex := i / 8
		bitInByteIndex := i % 8
		mask := (byte)(1 << bitInByteIndex)
		GeDbl(r, r)
		if (s[byteIndex] & mask) != 0 {
			GeAdd(r, r, p)
		}
	}
}

// GeToAffine sets R to the affine coordinates of P
func GeToAffine(r *AffineGroupElement, p *ProjectiveGroupElement) {
	zInv := &FieldElement{}
	feInvert(zInv, &p.z)
	feMultiply(&r.x, &p.x, zInv)
	feMultiply(&r.y, &p.y, zInv)
}

// GeEqual returns 1 if P == Q and 0 otherwise
func GeEqual(p, q *AffineGroupElement) int {
	xEqual := feEqual(&p.x, &q.x)
	yEqual := feEqual(&p.y, &q.y)
	v := xEqual + yEqual
	return subtle.ConstantTimeEq(int32(v), 2)
}
