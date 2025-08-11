package polynomial

import (
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"strconv"
	"strings"
)

// Polynomial is a polynomial over a field. coeffs[i] is the i'th degree coefficient.
// I.e. for a 2nd degree polynomial, p(X) = coeffs[2] * X^2 + coeffs[1] * X^1 + coeffs[0]
type Polynomial struct {
	coeffs []ec.Scalar
}

// Eval evaluates using Horner's method: https://en.wikipedia.org/wiki/Horner%27s_method
func (p *Polynomial) Eval(x ec.Scalar) ec.Scalar {
	sum := x.Field().Zero()
	for i := len(p.coeffs) - 1; i > 0; i-- {
		sum = sum.Add(p.coeffs[i]).Multiply(x)
	}
	return sum.Add(p.coeffs[0])
}

// Coefficients returns the coefficients of the polynomial
func (p *Polynomial) Coefficients() []ec.Scalar {
	return p.coeffs
}

// NewPolynomial constructs a polynomial with the given coefficients.
// E.g., Polynomial(2, 7, 3) is e.g. the polynomial p(X) = 2x^2 + 7x + 3.
func NewPolynomial(coeffs ...ec.Scalar) *Polynomial {
	return &Polynomial{coeffs}
}

// NewRandomPolynomial constructs a random degree t polynomial with constant degree coefficient c0.
// I.e. the result is p(X) = ct * X^t + ... + c1 * X^1 + c0 * X^0
// where ct, ct-1, ..., c0 are randomly chosen.
func NewRandomPolynomial(t int, c0 ec.Scalar) *Polynomial {
	coeffs := make([]ec.Scalar, t+1)
	coeffs[0] = c0
	for i := 1; i < len(coeffs); i++ {
		coeffs[i] = c0.Field().NewRandomScalar()
	}
	return &Polynomial{coeffs: coeffs}
}

func (p *Polynomial) Equals(o *Polynomial) bool {
	if len(p.coeffs) != len(o.coeffs) {
		return false
	}
	for i, v := range p.coeffs {
		if v != o.coeffs[i] {
			return false
		}
	}
	return true
}

func (p *Polynomial) String() string {
	var sb strings.Builder
	for i := len(p.coeffs) - 1; i > 0; i-- {
		_, _ = sb.WriteString(p.coeffs[i].Value().String())
		_, _ = sb.WriteString("X^")
		_, _ = sb.WriteString(strconv.Itoa(i + 1))
		_, _ = sb.WriteString("+")
	}
	if len(p.coeffs) > 0 {
		_, _ = sb.WriteString(p.coeffs[0].Value().String())
	} else {
		return ""
	}
	return sb.String()
}
