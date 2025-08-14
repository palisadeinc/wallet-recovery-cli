package bits

type Bit uint8

const (
	False Bit = 0
	True  Bit = 1
)

func FromBool(v bool) Bit {
	if v {
		return True
	}
	return False
}

func (b Bit) Neg() Bit {
	return b ^ 1
}

func (b Bit) Bool() bool {
	return (b & 1) == True
}
