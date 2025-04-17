package math

import (
	"crypto/ed25519"
	"crypto/sha512"
	"math/big"
	"testing"
)

var curveNames = []string{"P-224", "P-256", "P-384", "P-521", "secp256k1", "ED-25519"}

func TestPointEquals(t *testing.T) {
	for _, curveName := range curveNames {
		curve, err := NewCurve(curveName)
		requireNoError(t, err)

		requireFalse(t, curve.G().Equals(curve.O()))
		requireFalse(t, curve.O().Equals(curve.G()))
		requireTrue(t, curve.O().Equals(curve.O()))
		requireTrue(t, curve.G().Equals(curve.G()))
	}
}

func TestPointEncodeDecode(t *testing.T) {
	for _, curveName := range curveNames {
		curve, err := NewCurve(curveName)
		requireNoError(t, err)

		for _, p := range []Point{curve.O(), curve.G()} {
			b := p.Encode()
			pPrime, err := curve.DecodePoint(b)
			requireNoError(t, err)
			requireTrue(t, p.Equals(pPrime))
		}

		for i := 0; i < 10; i++ {
			s := curve.NewRandomScalar()
			p := curve.G().Mul(s)

			var encodedPoint []byte
			encodedPoint = p.Encode()
			decodedPoint, err := curve.DecodePoint(encodedPoint)
			requireNoError(t, err)
			requireTrue(t, p.Equals(decodedPoint))
		}
	}
}

func TestInfinityCornerCases(t *testing.T) {
	for _, curveName := range curveNames {
		curve, err := NewCurve(curveName)
		requireNoError(t, err)
		g := curve.G()
		o := curve.O()
		p := curve.G().Mul(curve.NewRandomScalar())

		zero := curve.NewScalarBigInt(new(big.Int).SetInt64(0))

		r := g.Mul(zero)
		requireTrue(t, r.Equals(curve.O()))

		r = p.Mul(zero)
		requireTrue(t, r.Equals(curve.O()))

		r = o.Mul(zero)
		requireTrue(t, r.Equals(curve.O()))

		r = o.Mul(zero)
		requireTrue(t, r.Equals(curve.O()))

		r = o.Mul(curve.NewRandomScalar())
		requireTrue(t, r.Equals(curve.O()))

		r = o.Mul(curve.NewRandomScalar())
		requireTrue(t, r.Equals(curve.O()))
	}
}

func TestPointAddSubtract(t *testing.T) {
	for _, curveName := range curveNames {
		curve, err := NewCurve(curveName)
		requireNoError(t, err)

		g2 := curve.G().Add(curve.G())
		requireFalse(t, curve.G().Equals(g2))

		g := g2.Sub(curve.G())
		requireTrue(t, curve.G().Equals(g))

		g = curve.G().Add(curve.O())
		requireTrue(t, curve.G().Equals(g))
	}
}

func TestPointMultiply(t *testing.T) {
	for _, curveName := range curveNames {
		curve, err := NewCurve(curveName)
		requireNoError(t, err)

		nMinus1 := new(big.Int).Sub(curve.impl.Params().N, big.NewInt(1))
		g2Add := curve.G().Add(curve.G())
		gNeg := curve.G().Neg()

		g2Mul := curve.G().Mul(curve.NewScalarInt(2))
		requireTrue(t, g2Add.Equals(g2Mul))

		o := curve.G().Mul(curve.NewScalarBigInt(curve.impl.Params().N))
		requireTrue(t, curve.O().Equals(o))

		gNegMul := curve.G().Mul(curve.NewScalarBigInt(nMinus1))
		requireTrue(t, gNeg.Equals(gNegMul))
	}
}

func TestECDSASignature(t *testing.T) {
	for _, curveName := range curveNames {
		if curveName == "ED-25519" {
			continue
		}

		curve, err := NewCurve(curveName)
		requireNoError(t, err)

		x := curve.NewRandomScalar()
		Y := curve.G().Mul(x)

		messageHash := []byte("Here is a message hash")
		z := curve.NewScalarBytes(messageHash)

		k := curve.NewRandomScalar()
		R := curve.G().Mul(k)

		Rx, _ := R.Coordinates()
		r := curve.NewScalarBigInt(Rx)

		kInv := k.Inv()

		s := kInv.Mul(z.Add(r.Mul(x)))
		sInv := s.Inv()

		u1 := sInv.Mul(z)
		u2 := sInv.Mul(r)

		Gu1 := curve.G().Mul(u1)
		Pku2 := Y.Mul(u2)

		RPrime := Gu1.Add(Pku2)
		RxPrime, _ := RPrime.Coordinates()
		requireNoError(t, err)
		rPrime := curve.NewScalarBigInt(RxPrime)

		requireTrue(t, r.Equals(rPrime))
	}
}

func TestEd25519Signature(t *testing.T) {
	curve, err := NewCurve("ED-25519")
	requireNoError(t, err)

	x := curve.NewRandomScalar()
	Y := curve.G().Mul(x)

	message := []byte("Here is a message")

	r := curve.NewRandomScalar()
	R := curve.G().Mul(r)

	hash := sha512.New()
	hash.Write(R.Encode())
	hash.Write(Y.Encode())
	hash.Write(message)
	hh := hash.Sum(nil)
	reverseSlice(hh)
	h := curve.NewScalarBytes(hh)

	s := h.Mul(x).Add(r)

	signature := make([]byte, 64)
	copy(signature[:], R.Encode())
	copy(signature[32:], s.Encode())
	reverseSlice(signature[32:])

	requireTrue(t, ed25519.Verify(Y.Encode(), message, signature))

	t1 := Y.Mul(h)
	t2 := curve.G().Mul(s)
	R2 := t2.Sub(t1)
	requireTrue(t, R.Equals(R2))
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Logf(err.Error())
		t.FailNow()
	}
}

func requireTrue(t *testing.T, b bool) {
	t.Helper()
	if !b {
		t.Logf("expected true")
		t.FailNow()
	}
}

func requireFalse(t *testing.T, b bool) {
	t.Helper()
	if b {
		t.Logf("expected false")
		t.FailNow()
	}
}
