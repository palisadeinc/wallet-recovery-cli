package ec

import (
	"fmt"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

type bls12381PairingCurveParams struct {
	name string
	e1   Curve
	e2   Curve
	gt   Field
}

type bls12381PairingCurve struct {
	params *bls12381PairingCurveParams
}

func newBLS12381() PairingCurve {
	initFields()
	initCurves()

	params := &bls12381PairingCurveParams{
		name: "BLS-12-381",
		e1:   curves[curveBLS12381E1],
		e2:   curves[curveBLS12381E2],
		gt:   fields[fieldBLS12381GT],
	}

	return bls12381PairingCurve{
		params: params,
	}
}

func (c bls12381PairingCurve) Name() string {
	return c.params.name
}

func (c bls12381PairingCurve) Equals(o PairingCurve) bool {
	return c.params.name == o.Name()
}

func (c bls12381PairingCurve) E1() Curve {
	return c.params.e1
}

func (c bls12381PairingCurve) E2() Curve {
	return c.params.e2
}

func (c bls12381PairingCurve) GT() Field {
	return c.params.gt
}

func (c bls12381PairingCurve) Pair(a, b Point) (Element, error) {
	if !a.Curve().Equals(c.params.e1) || !a.IsInLargeSubgroup() {
		return Element{}, fmt.Errorf("the first point is not from the elliptic curve %s or not in the correct subgroup", c.params.e1.Name())
	}
	if !b.Curve().Equals(c.params.e2) || !b.IsInLargeSubgroup() {
		return Element{}, fmt.Errorf("the second point is not from the elliptic curve %s or not in the correct subgroup", c.params.e2.Name())
	}

	var aAffine bls12381.G1Affine
	aAffine.FromJacobian(toBLS12381E1Point(a.value))

	var bAffine bls12381.G2Affine
	bAffine.FromJacobian(toBLS12381E2Point(b.value))

	res, err := bls12381.Pair([]bls12381.G1Affine{aAffine}, []bls12381.G2Affine{bAffine})
	if err != nil {
		return Element{}, fmt.Errorf("pairing error: %s", err)
	}

	return Scalar{
		field: c.params.gt,
		value: &res,
	}, nil
}
