package ers

import (
	"fmt"
	"github.com/palisadeinc/mpc-recovery/math"
)

func reconstruct(shares map[int]math.Scalar, sharingType string, threshold int) (secret math.Scalar, err error) {
	if len(shares) < 2 {
		return math.Scalar{}, fmt.Errorf("not enough shares to reconstruct: %d", len(shares))
	}
	if threshold < 1 || threshold >= len(shares) {
		return math.Scalar{}, fmt.Errorf("not enough shares for threshold: %d", threshold)
	}

	switch sharingType {
	case additive:
		return additiveReconstruct(shares), nil
	case multiplicative:
		return multiplicativeReconstruct(shares), nil
	case shamir:
		return shamirReconstruct(shares, threshold)
	}
	return math.Scalar{}, fmt.Errorf("unsupported sharing type: %s", sharingType)
}

func additiveReconstruct(shares map[int]math.Scalar) math.Scalar {
	result := shares[0].Curve().NewScalarInt(0)
	for _, share := range shares {
		result = result.Add(share)
	}
	return result
}

func multiplicativeReconstruct(shares map[int]math.Scalar) math.Scalar {
	result := shares[0].Curve().NewScalarInt(1)
	for _, share := range shares {
		result = result.Mul(share)
	}
	return result
}

func shamirReconstruct(shares map[int]math.Scalar, threshold int) (math.Scalar, error) {
	curve := shares[0].Curve()

	xs := make([]math.Scalar, 0, len(shares))
	ys := make([]math.Scalar, 0, len(shares))

	for i := range shares {
		xs = append(xs, curve.NewScalarInt(i+1))
		ys = append(ys, shares[i])
	}
	return math.LagrangeReconstruct(curve.NewScalarInt(0), threshold, xs, ys)
}
