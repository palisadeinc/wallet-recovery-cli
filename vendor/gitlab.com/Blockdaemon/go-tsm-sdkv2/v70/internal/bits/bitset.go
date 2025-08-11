package bits

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"io"
	"math/bits"
	"strings"
	"sync"
)

const boundsIndex = "index out of range [%d] with length %d"
const unsupportedGFLength = "unsupported galois reduction size %d"

var reductionPolynomials map[int]BitSet
var reductionPolynomialsInit sync.Once

type BitSet struct {
	bitLength int
	limbs     []uint64
}

func NewZeroSet(bitLength int) BitSet {
	limbCount := (bitLength + 63) / 64
	return BitSet{
		bitLength: bitLength,
		limbs:     make([]uint64, limbCount),
	}
}

func NewRandomSet(bitLength int) BitSet {
	s, err := NewFromReader(random.Reader, bitLength)
	if err != nil {
		panic(err)
	}
	return s
}

func NewFromBytes(input []byte) BitSet {
	s := NewZeroSet(8 * len(input))

	for i := 0; i < len(s.limbs); i++ {
		b := input[i*8:]
		if len(b) < 8 {
			b = make([]byte, 8)
			copy(b, input[i*8:])
		}
		s.limbs[i] = binary.LittleEndian.Uint64(b)
	}
	return s
}

func NewFromReader(reader io.Reader, bitLength int) (BitSet, error) {
	if bitLength == 0 {
		return NewZeroSet(0), nil
	}
	bytesToRead := (bitLength + 7) / 8
	b := make([]byte, bytesToRead)
	_, err := reader.Read(b)
	if err != nil {
		return BitSet{}, err
	}

	s := NewFromBytes(b)
	s.Resize(bitLength)
	return s, nil
}

func (s BitSet) Serialize() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(s.Length()))
	b = append(b, s.Bytes()...)
	return b
}

func Deserialize(data []byte) (BitSet, error) {
	if len(data) < 8 {
		return BitSet{}, fmt.Errorf("invalid data length %d", len(data))
	}
	bitLength := int(binary.LittleEndian.Uint64(data))
	if bitLength < 0 || (bitLength+7)/8 != len(data)-8 {
		return BitSet{}, fmt.Errorf("invalid length %d", bitLength)
	}

	s := NewFromBytes(data[8:])
	s.Resize(bitLength)
	return s, nil
}

// Bytes returns the BitSet as a little endian byte array. If the BitSet length is not a multiple of eight the
// last byte is zero padded. This means that there are different BitSets that return the same output. If this is a
// problem use Serialize instead.
func (s BitSet) Bytes() []byte {
	limbCount := len(s.limbs)
	r := make([]byte, 8*limbCount)
	for i := 0; i < limbCount; i++ {
		binary.LittleEndian.PutUint64(r[i*8:], s.limbs[i])
	}

	byteCount := (s.Length() + 7) / 8
	return r[:byteCount]
}

func (s BitSet) WriteTo(writer io.Writer) (n int64, err error) {
	if s.Length() == 0 {
		return 0, fmt.Errorf("cannot write bitset of length 0")
	}
	buf := bytes.NewBuffer(s.Bytes())
	return buf.WriteTo(writer)
}

func (s BitSet) Length() int {
	return s.bitLength
}

func (s BitSet) set(pos int, val Bit) {
	if pos < 0 || pos >= s.Length() {
		panic(fmt.Sprintf(boundsIndex, pos, s.Length()))
	}

	limbIndex, bitIndex := decodePosition(pos)

	a := uint64(1) << bitIndex
	b := uint64(val) << bitIndex

	s.limbs[limbIndex] = (s.limbs[limbIndex] & ^a) | b
}

func (s BitSet) toggle(pos int) {
	if pos < 0 || pos >= s.Length() {
		panic(fmt.Sprintf(boundsIndex, pos, s.Length()))
	}

	limbIndex, bitIndex := decodePosition(pos)

	s.limbs[limbIndex] ^= 1 << bitIndex
}

func (s BitSet) get(pos int) Bit {
	if pos < 0 || pos >= s.Length() {
		panic(fmt.Sprintf(boundsIndex, pos, s.Length()))
	}

	limbIndex, bitIndex := decodePosition(pos)

	return Bit((s.limbs[limbIndex] >> bitIndex) & 1)
}

func (s BitSet) Bools() []bool {
	length := s.Length()

	bools := make([]bool, length)

	for i := 0; i < length; i++ {
		bools[i] = s.get(i).Bool()
	}

	return bools
}

func (s BitSet) Get(bit int) Bit {
	return s.get(bit)
}

func (s BitSet) IsSet(bit int) bool {
	return s.Get(bit) != 0x00
}

func (s BitSet) Assign(bit int, val Bit) {
	s.set(bit, val)
}

func (s *BitSet) Append(val Bit) {
	idx := s.Length()
	s.Resize(idx + 1)
	s.set(idx, val)
}

func (s BitSet) Set(bit int) {
	s.set(bit, True)
}

func (s BitSet) Clear(bit int) {
	s.set(bit, False)
}

func (s BitSet) Toggle(bit int) {
	s.toggle(bit)
}

func (s BitSet) ShiftLeft(count int) {
	limbCount := count / 64
	bitCount := count % 64

	if limbCount > 0 {
		for i := len(s.limbs) - 1; i-limbCount >= 0; i-- {
			s.limbs[i] = s.limbs[i-limbCount]
		}
		for i := limbCount - 1; i >= 0; i-- {
			s.limbs[i] = 0
		}
	}

	if bitCount > 0 {
		var carry uint64 = 0
		for i := 0; i < len(s.limbs); i++ {
			tmp := s.limbs[i] >> (64 - bitCount)
			s.limbs[i] = (s.limbs[i] << bitCount) | carry
			carry = tmp
		}
	}

	s.Resize(s.Length())
}

func (s BitSet) OnesCount() int {
	count := 0
	for i := 0; i < len(s.limbs); i++ {
		count += bits.OnesCount64(s.limbs[i])
	}
	return count
}

func (s *BitSet) SetBitSet(bs BitSet) {
	limbDifference := len(bs.limbs) - len(s.limbs)

	if limbDifference > 0 {
		s.limbs = append(s.limbs, make([]uint64, limbDifference)...)
	} else if limbDifference < 0 {
		s.limbs = s.limbs[0 : len(s.limbs)+limbDifference]
	}

	copy(s.limbs, bs.limbs)
	s.bitLength = bs.bitLength
}

func (s BitSet) Xor(os ...BitSet) {
	for _, e := range os {
		for j := 0; j < len(e.limbs) && j < len(s.limbs); j++ {
			s.limbs[j] ^= e.limbs[j]
		}
	}
}

func (s BitSet) Or(os ...BitSet) {
	for _, e := range os {
		for j := 0; j < len(e.limbs) && j < len(s.limbs); j++ {
			s.limbs[j] |= e.limbs[j]
		}
	}
}
func (s BitSet) And(os ...BitSet) {
	for _, e := range os {
		for j := 0; j < len(e.limbs) && j < len(s.limbs); j++ {
			s.limbs[j] &= e.limbs[j]
		}
	}
}

func (s BitSet) Not() {
	for i := 0; i < len(s.limbs); i++ {
		s.limbs[i] = ^s.limbs[i]
	}
	s.Resize(s.Length())
}

func (s BitSet) Clone() BitSet {
	limbs := make([]uint64, len(s.limbs))
	copy(limbs, s.limbs)
	return BitSet{
		bitLength: s.Length(),
		limbs:     limbs,
	}
}

func (s BitSet) CloneResize(bitLength int) BitSet {
	limbCount := (bitLength + 63) / 64

	limbs := make([]uint64, limbCount)
	copy(limbs, s.limbs)

	set := BitSet{
		bitLength: bitLength,
		limbs:     limbs,
	}

	set.Resize(bitLength)
	return set
}

func (s BitSet) CloneAssign(bit int, val Bit) BitSet {
	set := s.CloneResize(bit + 1)
	set.Assign(bit, val)
	return set
}

func (s *BitSet) Resize(bitLength int) {
	if s.Length() != bitLength {
		limbCount := (bitLength + 63) / 64
		limbs := make([]uint64, limbCount)
		copy(limbs, s.limbs)

		s.bitLength = bitLength
		s.limbs = limbs
	}

	bitsToClear := 64 - (s.Length() % 64)
	if bitsToClear != 64 {
		s.limbs[len(s.limbs)-1] &= uint64(0xFFFFFFFFFFFFFFFF) >> bitsToClear
	}
}

func (s BitSet) KeepOrClear(b Bit) {
	for j := 0; j < len(s.limbs); j++ {
		s.limbs[j] *= uint64(b)
	}
}

func NewSetFromBools(bools []bool) BitSet {
	set := NewZeroSet(len(bools))

	for i, v := range bools {
		set.set(i, FromBool(v))
	}

	return set
}

func NewSetFromBits(bits []Bit) BitSet {
	byteCount := (len(bits) + 7) / 8
	set := NewZeroSet(8 * byteCount)

	for i, v := range bits {
		set.set(i, v)
	}

	return set
}

func ParseString(val string) BitSet {
	set := NewZeroSet(len(val))

	j := len(val) - 1
	for _, c := range val {
		if c == '0' {
			set.set(j, False)
		} else {
			set.set(j, True)
		}
		j--
	}
	return set
}

func (s BitSet) Subset(start, end int) BitSet {
	if start >= end {
		set := NewZeroSet(0)
		return set
	}

	firstLimbIndex, firstBitIndex := decodePosition(start)
	lastLimbIndex, _ := decodePosition(end - 1)

	limbs := make([]uint64, lastLimbIndex-firstLimbIndex+1)
	copy(limbs, s.limbs[firstLimbIndex:])

	if firstBitIndex > 0 {
		carry := uint64(0)
		for i := len(limbs) - 1; i >= 0; i-- {
			tmp := limbs[i] << (64 - firstBitIndex)
			limbs[i] = (limbs[i] >> firstBitIndex) | carry
			carry = tmp
		}
	}

	lastLimbIndex, lastBitIndex := decodePosition(end - start - 1)
	limbs = limbs[:lastLimbIndex+1]

	mask := uint64(0xFFFFFFFFFFFFFFFF) >> (63 - lastBitIndex)
	limbs[lastLimbIndex] &= mask

	return BitSet{
		bitLength: end - start,
		limbs:     limbs,
	}
}

func Concat(sets ...BitSet) BitSet {
	if len(sets) == 0 {
		return NewZeroSet(0)
	}

	bitLength := 0
	for _, s := range sets {
		bitLength = bitLength + s.Length()
	}

	res := sets[len(sets)-1].CloneResize(bitLength)
	for i := len(sets) - 2; i >= 0; i-- {
		res.ShiftLeft(sets[i].Length())
		res.Xor(sets[i])
	}

	return res
}

func GF2Reduction(x BitSet, reductionSize int) BitSet {
	if x.Length() > 2*reductionSize {
		panic("reduction from value larger than twice the reduction polynomial is not implemented yet")
	}

	if x.Length() <= reductionSize {
		return x
	}

	reductionPolynomial := selectReductionPolynomial(reductionSize)

	zeroSet := NewZeroSet(1)

	topBlock := x.Subset(reductionSize, x.Length())
	if !topBlock.Equal(zeroSet) {
		reduction := GF2Mul(topBlock, reductionPolynomial)

		if reduction.Length() <= reductionSize {
			bottomBlock := x.Subset(0, reductionSize)
			bottomBlock.Xor(reduction)
			return bottomBlock
		} else {
			reduction.Xor(x.Subset(0, reductionSize))
			topBlock = reduction.Subset(reductionSize, reduction.Length())

			if topBlock.Equal(zeroSet) {
				return reduction.Subset(0, reductionSize)
			}

			reduction2 := GF2Mul(topBlock, reductionPolynomial)
			bottomBlock := reduction.Subset(0, reductionSize)
			bottomBlock.Xor(reduction2.Subset(0, reductionSize)) // Guaranteed that top bits are 0 here.

			return bottomBlock
		}
	} else {
		bottomBlock := x.Subset(0, reductionSize)
		return bottomBlock
	}
}

func selectReductionPolynomial(reductionSize int) BitSet {
	reductionPolynomialsInit.Do(func() {
		reductionPolynomials = map[int]BitSet{}
		for _, size := range []int{32, 40, 60, 64, 80, 128, 160, 256} {
			// Irreducible polynomials taken from (1 is implied, the rest are x powers):
			//   https://shiftleft.com/mirrors/www.hpl.hp.com/techreports/98/HPL-98-135.pdf
			// P(2^32) =   32,  7,  3,  2
			// P(2^40) =   40,  5,  4,  3
			// P(2^60) =   60,  1
			// P(2^64) =   64,  4,  3,  1
			// P(2^80) =   80,  9,  4,  2
			// P(2^128) = 128,  7,  2,  1
			// P(2^160) = 160,  5,  3,  2
			// P(2^256) = 256, 10,  5,  2
			switch size {
			case 32:
				reductionPolynomial := NewZeroSet(8)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(2)
				reductionPolynomial.Set(3)
				reductionPolynomial.Set(7)
				reductionPolynomials[size] = reductionPolynomial
			case 40:
				reductionPolynomial := NewZeroSet(6)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(3)
				reductionPolynomial.Set(4)
				reductionPolynomial.Set(5)
				reductionPolynomials[size] = reductionPolynomial
			case 60:
				reductionPolynomial := NewZeroSet(2)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(1)
				reductionPolynomials[size] = reductionPolynomial
			case 64:
				reductionPolynomial := NewZeroSet(5)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(1)
				reductionPolynomial.Set(3)
				reductionPolynomial.Set(4)
				reductionPolynomials[size] = reductionPolynomial
			case 80:
				reductionPolynomial := NewZeroSet(10)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(2)
				reductionPolynomial.Set(4)
				reductionPolynomial.Set(9)
				reductionPolynomials[size] = reductionPolynomial
			case 128:
				reductionPolynomial := NewZeroSet(8)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(1)
				reductionPolynomial.Set(2)
				reductionPolynomial.Set(7)
				reductionPolynomials[size] = reductionPolynomial
			case 160:
				reductionPolynomial := NewZeroSet(6)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(2)
				reductionPolynomial.Set(3)
				reductionPolynomial.Set(5)
				reductionPolynomials[size] = reductionPolynomial
			case 256:
				reductionPolynomial := NewZeroSet(11)
				reductionPolynomial.Set(0)
				reductionPolynomial.Set(2)
				reductionPolynomial.Set(5)
				reductionPolynomial.Set(10)
				reductionPolynomials[size] = reductionPolynomial
			}
		}
	})

	if reductionPolynomial, hasReductionPolynomial := reductionPolynomials[reductionSize]; hasReductionPolynomial {
		return reductionPolynomial
	}
	panic(fmt.Sprintf(unsupportedGFLength, reductionSize))
}

func GF2Mul(a, b BitSet) BitSet {
	if len(a.limbs) <= 2 && len(b.limbs) <= 2 {
		return gF2Mul128(a, b)
	} else {
		return gF2MulOptimized(a, b)
	}
}

func gF2Mul128(a, b BitSet) BitSet {
	var x0, x1 uint64
	var y0, y1 uint64

	if len(a.limbs) > 0 {
		x0 = a.limbs[0]
	}
	if len(a.limbs) > 1 {
		x1 = a.limbs[1]
	}
	if len(b.limbs) > 0 {
		y0 = b.limbs[0]
	}
	if len(b.limbs) > 1 {
		y1 = b.limbs[1]
	}

	v := _gF2Mul128(x1, x0, y1, y0)

	resultBitLength := a.Length() + b.Length()
	resultLimbCount := (resultBitLength + 63) / 64

	s := BitSet{
		bitLength: resultBitLength,
		limbs:     v[:resultLimbCount],
	}
	return s
}

func gF2MulOptimized(a, b BitSet) BitSet {
	if a.Length() > b.Length() {
		tmp := a
		a = b
		b = tmp
	}

	result := NewZeroSet(64 * (len(a.limbs) + len(b.limbs)))
	aLimbPairCount := len(a.limbs)/2 + len(a.limbs)%2
	bLimbPairCount := len(b.limbs)/2 + len(b.limbs)%2

	for i := 0; i < aLimbPairCount; i++ {
		shiftLimbsOffset := i * 2
		aLimbPair := a.limbs[i*2:]

		for j := 0; j < bLimbPairCount; j++ {
			shiftLimbCount := shiftLimbsOffset + (j * 2)
			bLimbPair := b.limbs[j*2:]

			var x0, x1, y0, y1 uint64
			x0 = aLimbPair[0]
			y0 = bLimbPair[0]
			intermediateResultLimbCount := 2
			if len(aLimbPair) > 1 {
				x1 = aLimbPair[1]
				intermediateResultLimbCount += 1
			}
			if len(bLimbPair) > 1 {
				y1 = bLimbPair[1]
				intermediateResultLimbCount += 1
			}

			res256 := _gF2Mul128(x1, x0, y1, y0)
			for k := 0; k < intermediateResultLimbCount; k++ {
				result.limbs[shiftLimbCount+k] = result.limbs[shiftLimbCount+k] ^ res256[k]
			}
		}
	}

	resultBitLength := a.Length() + b.Length()
	resultLimbCount := (resultBitLength + 63) / 64

	result.bitLength = resultBitLength
	result.limbs = result.limbs[:resultLimbCount]

	return result
}

func (s BitSet) Equal(o BitSet) bool {
	var longest, shortest BitSet
	if s.Length() > o.Length() {
		longest = s
		shortest = o
	} else {
		longest = o
		shortest = s
	}

	for i := range shortest.limbs {
		if shortest.limbs[i] != longest.limbs[i] {
			return false
		}
	}

	for i := len(shortest.limbs); i < len(longest.limbs); i++ {
		if longest.limbs[i] != 0 {
			return false
		}
	}

	return true
}

func (s BitSet) String() string {
	sb := strings.Builder{}
	for i := s.Length() - 1; i >= 0; i-- {
		if s.get(i) == True {
			sb.WriteString("1")
		} else {
			sb.WriteString("0")
		}
	}

	return sb.String()
}

func (s BitSet) MarshalBinary() ([]byte, error) {
	return s.Serialize(), nil
}

func (s *BitSet) UnmarshalBinary(data []byte) error {
	b, err := Deserialize(data)
	if err != nil {
		return nil
	}
	s.bitLength = b.bitLength
	s.limbs = b.limbs
	return nil
}

func decodePosition(pos int) (uint, uint) {
	limb := uint(pos / 64)
	index := uint(pos % 64)

	return limb, index
}
