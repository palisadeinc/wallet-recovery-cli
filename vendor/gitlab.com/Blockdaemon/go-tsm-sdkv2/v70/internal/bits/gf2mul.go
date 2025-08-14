//go:build !amd64

package bits

func _gF2Mul128(a1, a0, b1, b0 uint64) [4]uint64 {
	return genericGF2Mul128(a1, a0, b1, b0)
}
