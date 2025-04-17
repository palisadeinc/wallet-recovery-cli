package polynomial

import (
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/caching"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
	"strconv"
	"strings"
)

const lagrangeCoefficientsCacheSize = 1024

var lagrangeCache = caching.NewLRUCache(lagrangeCoefficientsCacheSize)

// Lagrange computes lagrange coefficients required to compute p(s) of the degree t polynomial p given
// xs[0], xs[1] ..., xs[t]
func Lagrange(s ec.Scalar, t int, xs []ec.Scalar) []ec.Scalar {
	if t < 1 {
		panic("invalid degree")
	}
	if len(xs) < t+1 {
		panic("too few points to interpolate for the given threshold")
	}

	f := func(key interface{}, data interface{}) (interface{}, error) {
		L := make([]ec.Scalar, len(xs))

		sum := s.Field().Zero()
		for i := range xs {
			L[i] = weight(i, xs).Divide(s.Subtract(xs[i]))
			sum = sum.Add(L[i])
		}
		sum = sum.Invert()
		for i := range xs {
			L[i] = L[i].Multiply(sum)
		}

		return L, nil
	}

	key := newLCacheKey(s, t, xs)
	value, err := lagrangeCache.GetOrSet(key, nil, f)
	if err != nil {
		panic(fmt.Sprintf("cache error: %s", err))
	}

	return value.([]ec.Scalar)
}

// LagrangePlayers computes lagrange coefficients required to compute p(s) of the degree t polynomial p given
// players[0]+1, players[1]+1 ..., players[n-1]+1. The returned integer indicates the position of playerIndex
// in the result and is -1 if playerIndex was not found in the list of players.
func LagrangePlayers(s ec.Scalar, t, playerIndex int, players []int) ([]ec.Scalar, int) {
	field := s.Field()
	playerIndexInArray := -1

	xs := make([]ec.Scalar, len(players))
	for i, player := range players {
		if player == playerIndex {
			playerIndexInArray = i
		}
		xs[i] = field.NewScalarIntWithModularReduction(players[i] + 1)
	}
	return Lagrange(s, t, xs), playerIndexInArray
}

// Interpolate computes p(s) of the degree t polynomial p given p(x[0]), p(x[1]), ..., p(x[t])
func Interpolate(s ec.Scalar, t int, xs, ys []ec.Scalar) ec.Scalar {
	if t < 1 {
		panic("invalid degree")
	}
	if len(xs) != len(ys) {
		panic("mismatch between number of x and y values")
	}

	xs = xs[0 : t+1]
	L := Lagrange(s, t, xs)

	res := s.Field().Zero()
	for i := range L {
		res = res.Add(ys[i].Multiply(L[i]))
	}

	return res
}

func InterpolatePlayers(s ec.Scalar, t int, m map[int]ec.Scalar) ec.Scalar {
	xs := make([]ec.Scalar, 0, len(m))
	ys := make([]ec.Scalar, 0, len(m))

	for x, y := range m {
		xs = append(xs, y.Field().NewScalarIntWithModularReduction(x+1))
		ys = append(ys, y)
	}
	return Interpolate(s, t, xs, ys)
}

// InterpolateInExponent computes g^{p(s)} given g^{p(x[0])}, g^{p(x[1])}, ..., g^{p(x[t])} where g is a generator of
// the elliptic curve group
func InterpolateInExponent(s ec.Scalar, t int, xs []ec.Scalar, gys []ec.Point) ec.Point {
	if t < 1 {
		panic("invalid degree")
	}
	if len(xs) != len(gys) {
		panic("mismatch between number of x and y values")
	}

	xs = xs[0 : t+1]
	L := Lagrange(s, t, xs)

	res := gys[0].Curve().O()
	for i := range L {
		res = res.Add(gys[i].MultiplyVarTime(L[i]))
	}

	return res
}

func InterpolatePlayersInExponent(s ec.Scalar, t int, m map[int]ec.Point) ec.Point {
	xs := make([]ec.Scalar, 0, len(m))
	ys := make([]ec.Point, 0, len(m))

	for x, y := range m {
		xs = append(xs, y.Curve().Zn().NewScalarIntWithModularReduction(x+1))
		ys = append(ys, y)
	}
	return InterpolateInExponent(s, t, xs, ys)
}

// AssertExponentsOnSamePolynomial checks that all exponents g^{p(x[0])}, g^{p(x[1])}, ..., g^{p(x[t])}, ... (based on
// the same generator of the elliptic curve group) are on the same polynomial.
func AssertExponentsOnSamePolynomial(t int, xs []ec.Scalar, gys []ec.Point) error {
	if t < 1 {
		panic("invalid degree")
	}
	if len(xs) < t+1 {
		panic("too few points to interpolate for the given threshold")
	}
	if len(xs) != len(gys) {
		panic("mismatch between number of x and g^y values")
	}

	var diffEngine *DifferenceEngineInExponent
	if smoothSequence(xs) {
		diffEngine = NewDifferenceEngineInExponent(gys[:t+1])
	}

	for i := 0; i < len(gys)-t-1; i++ {
		var expected ec.Point
		if diffEngine != nil {
			expected = diffEngine.Next(1)
		} else {
			expected = InterpolateInExponent(xs[t+1+i], t, xs, gys)
		}
		if !gys[t+1+i].Equals(expected) {
			return fmt.Errorf("exponents are not on the same polynomial")
		}
	}

	return nil
}

func AssertPlayersExponentsOnSamePolynomial(t int, m map[int]ec.Point) error {
	xs := make([]ec.Scalar, 0, len(m))
	ys := make([]ec.Point, 0, len(m))

	for x, y := range m {
		xs = append(xs, y.Curve().Zn().NewScalarIntWithModularReduction(x+1))
		ys = append(ys, y)
	}
	return AssertExponentsOnSamePolynomial(t, xs, ys)
}

func weight(i int, x []ec.Scalar) ec.Scalar {
	result := x[0].Field().One()

	for j := 0; j < len(x); j++ {
		if i == j {
			continue
		}
		result = result.Multiply(x[i].Subtract(x[j]))
	}

	return result.Invert()
}

func smoothSequence(xs []ec.Scalar) bool {
	if len(xs) == 0 {
		return true
	}

	one := xs[0].Field().One()
	for i := 1; i < len(xs); i++ {
		if !xs[i-1].Equals(xs[i].Subtract(one)) {
			return false
		}
	}
	return true
}

func newLCacheKey(s ec.Scalar, t int, x []ec.Scalar) string {
	sb := strings.Builder{}
	sb.WriteString("lagrange_")
	sb.WriteString(s.Value().String())
	sb.WriteString("_")
	sb.WriteString(strconv.Itoa(t))
	sb.WriteString("_")
	for _, e := range x {
		sb.WriteString(e.Value().String())
		sb.WriteString("_")
	}
	sb.WriteString(s.Field().Modulus().String())
	return sb.String()
}
