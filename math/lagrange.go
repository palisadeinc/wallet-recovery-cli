package math

import "fmt"

// LagrangeReconstruct computes p(s) of the degree t polynomial p given p(x[0]), p(x[1]), ..., p(x[t]) using the
// Barycentric form of Lagrange interpolation.
func LagrangeReconstruct(s Scalar, t int, x, y []Scalar) (Scalar, error) {
	if len(x) != len(y) {
		return Scalar{}, fmt.Errorf("mismatch between number of x and y values")
	}
	if len(x) < t+1 {
		return Scalar{}, fmt.Errorf("too few points to interpolate for the given threshold")
	}
	for i := range x {
		if s.Equals(x[i]) {
			return Scalar{}, fmt.Errorf("nothing to reconstruct since the s value is already contained in the input")
		}
	}

	x = x[0 : t+1]
	y = y[0 : t+1]

	numerator := s.Curve().NewScalarInt(0)
	denominator := s.Curve().NewScalarInt(0)

	for j := range x {
		value := lPrime(j, x).Mul(s.Sub(x[j])).Inv()
		numerator = numerator.Add(value.Mul(y[j]))
		denominator = denominator.Add(value)
	}

	return numerator.Mul(denominator.Inv()), nil
}

func lPrime(i int, x []Scalar) Scalar {
	result := x[0].Curve().NewScalarInt(1)

	for j := 0; j < len(x); j++ {
		if i == j {
			continue
		}
		result = result.Mul(x[j].Sub(x[i]))
	}

	return result
}

// RecombineInExponent computes g^{p(s)} given g^{p(1)}, g^{p(2)}, ..., g^{p(t+1)} where g is a generator of the elliptic curve group.
func RecombineInExponent(s, t int, vals []Point) (Point, error) {
	return RecombineInExponent2(s, t, indicesArray(1, t+1), vals)
}

func indicesArray(start, length int) []int {
	x := make([]int, length)
	for i := 0; i < length; i++ {
		x[i] = i + start
	}
	return x
}

// RecombineInExponent2 computes g^{p(s)} given g^{p(x[0])}, g^{p(x[1])}, ..., g^{p(x[t])} where g is a generator of the elliptic curve group.
// Security note: This method uses variable time curve multiplication, since the exponents (i.e., the Lagrange coefficients) are assumed to be public.
func RecombineInExponent2(s, t int, x []int, vals []Point) (Point, error) {
	if len(x) < t+1 || len(vals) < t+1 {
		return Point{}, fmt.Errorf("cannot recombine in exponent for threshold %d with less than %d values", t, t+1)
	}
	x = x[:t+1]
	vals = vals[:t+1]

	L, err := Lagrange2(s, t, x, vals[0].curve)
	if err != nil {
		return Point{}, err
	}

	return dotInExponent(t, vals, L)
}

// Lagrange2 computes lagrange coefficients required to compute p(s) of the degree t polynomial p given p(x[0]), p(x[1]), ..., p(x[t]).
func Lagrange2(s, t int, x []int, curve Curve) ([]Scalar, error) {
	if len(x) < t+1 {
		return nil, fmt.Errorf("cannot compute lagrange coefficients for threshold %d with less than %d values", t, t+1)
	}
	x = x[:t+1]

	res := make([]Scalar, t+1)
	for i := 0; i < len(res); i++ {
		res[i] = curve.NewScalarInt(1)

		for m := 0; m < t+1; m++ {
			if m == i {
				continue
			}
			lhs := curve.NewScalarInt(s - x[m])
			rhs := curve.NewScalarInt(x[i] - x[m])
			c := lhs.Mul(rhs.Inv())
			res[i] = res[i].Mul(c)
		}
	}
	return res, nil

}

// Computes the 'dot' product a[0]^b[0] * a[1]^b[1] * ... * a[t]^b[t].
func dotInExponent(t int, a []Point, b []Scalar) (Point, error) {
	if len(a) < t+1 || len(b) < t+1 {
		return Point{}, fmt.Errorf("not enough elements")
	}

	var res = a[0].Mul(b[0])
	for k := 1; k < t+1; k++ {
		res = res.Add(a[k].Mul(b[k]))
	}
	return res, nil
}
