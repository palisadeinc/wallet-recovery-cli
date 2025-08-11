package poseidon

import "gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"

// sBox is the type of exponentiation to perform
type sBox int

const (
	cube    = 0 // x^3
	quint   = 1 // x^5
	sept    = 2 // x^7
	inverse = 3 // x^-1
)

// Exp mutates f by computing f^3, f^5, f^7 or f^-1 as described in https://eprint.iacr.org/2019/458.pdf page 8
func (s sBox) Exp(f ec.Scalar) ec.Scalar {
	switch s {
	case cube:
		t := f.Multiply(f)
		f = t.Multiply(f)
	case quint:
		t := f.Multiply(f)
		t = t.Multiply(t)
		f = t.Multiply(f)
	case sept:
		f2 := f.Multiply(f)
		f4 := f2.Multiply(f2)
		t := f2.Multiply(f4)
		f = f.Multiply(t)
	case inverse:
		f = f.Invert()
	}
	return f
}
