package infomac

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
)

// NewInfoMac constructs a new information-theoretic mac with the given statistical security level.
// The msgBitSize is the expected bit length of the messages to encode. This is only used for optimization; you can
// use msgBitSize=0 if in doubt.
func NewInfoMac(msgBitSize, securityLevel int) InfoMac {
	encoder := NewBlockEncoder(msgBitSize, securityLevel)
	mac := NewInfoMacFromEncoder(encoder)
	return mac

}

// NewInfoMacFromEncoder constructs an information theoretic mac. It computes a tag t on a bit message x as t = A*C(x)+B where
// * is bit-wise AND, + is xor, k=(A,B) is the mac key, and C is a binary encoder which a minimum distance
// corresponding to the security level of the mac.
func NewInfoMacFromEncoder(e MinDistEncoder) InfoMac {
	return InfoMac{
		encoder: e,
	}
}

type InfoMac struct {
	encoder MinDistEncoder
}

func (m InfoMac) GetTagSize(x bits.BitSet) int {
	return m.encoder.GetEncodingSize(x)
}

func (m InfoMac) GetKeySize(x bits.BitSet) int {
	return 2 * m.GetTagSize(x)
}

func (m InfoMac) GetSecurityLevel() int {
	return m.encoder.GetMinimumDistance()
}

func (m InfoMac) ComputeTag(x, key bits.BitSet) (tag bits.BitSet) {
	if key.Length() != m.GetKeySize(x) {
		panic(fmt.Sprintf("computing a tag on %d bits requires a key of size %d, but key has size %d", x.Length(), m.GetKeySize(x), key.Length()))
	}

	encoding := m.encoder.Encode(x)

	a := key.Subset(0, encoding.Length())
	b := key.Subset(encoding.Length(), 2*encoding.Length())

	encoding.And(a)
	encoding.Xor(b)

	return encoding
}
