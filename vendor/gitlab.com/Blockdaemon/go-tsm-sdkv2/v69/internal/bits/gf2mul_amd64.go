//go:build amd64

package bits

import "golang.org/x/sys/cpu"

//go:noescape
func __gF2Mul128(a1, a0, b1, b0 uint64, res *uint64)

func _gF2Mul128(a1, a0, b1, b0 uint64) [4]uint64 {
	if !cpu.X86.HasPCLMULQDQ {
		return genericGF2Mul128(a1, a0, b1, b0)
	}

	var res [4]uint64

	__gF2Mul128(a1, a0, b1, b0, &res[0])

	return res
}
