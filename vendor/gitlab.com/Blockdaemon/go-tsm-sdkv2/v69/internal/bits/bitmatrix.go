package bits

import (
	"fmt"
	bits2 "math/bits"
	"sync"
)

type BitMatrix []BitSet

func NewBitMatrix(cols int) BitMatrix {
	return make([]BitSet, cols)
}

func (m BitMatrix) Transpose() BitMatrix {
	rows, cols := m[0].Length(), len(m)
	dst := NewBitMatrix(rows)
	for i := 0; i < rows; i++ {
		dst[i] = NewZeroSet(cols)
	}
	m.transposeInto(dst, 0, cols, 0, rows)
	return dst
}

func (m BitMatrix) transposeInto(dst BitMatrix, colStart, colEnd, rowStart, rowEnd int) {
	rows := rowEnd - rowStart
	if rows == 0 {
		return
	}
	cols := colEnd - colStart
	if cols == 0 {
		return
	}

	if cols > 64 {
		wordCols := cols / 64
		var wg sync.WaitGroup
		wg.Add(wordCols)
		for i := 0; i < wordCols; i++ {
			i := i
			go func() {
				m.transposeInto(dst, colStart+64*i, colStart+64*(i+1), rowStart, rowEnd)
				wg.Done()
			}()
		}
		wg.Wait()

		m.transposeInto(dst, wordCols*64, colEnd, rowStart, rowEnd)
	} else if rows > 64 {
		wordRows := rows / 64

		var wg sync.WaitGroup
		wg.Add(wordRows)
		for i := 0; i < wordRows; i++ {
			i := i
			go func() {
				m.transposeInto(dst, colStart, colEnd, rowStart+64*i, rowStart+64*(i+1))
				wg.Done()
			}()
		}
		wg.Wait()

		m.transposeInto(dst, colStart, colEnd, rowStart+wordRows*64, rowEnd)
	} else {
		for i := 0; i < cols; i++ {
			// There is only one word pr column
			word := m[colStart+i].limbs[rowStart/64]
			for j := 0; j < rows; j++ {
				// Take the jth bit of word and set as ith bit in column j
				dst[rowStart+j].limbs[((colStart + i) / 64)] |= ((word >> j) & 1) << i
			}
		}
	}
}

func (m BitMatrix) String() string {
	var res string
	for i := 0; i < len(m); i++ {
		res = fmt.Sprintf("%s\n%s", res, m[i].String())
	}
	return res
}

func (m BitMatrix) Equals(o BitMatrix) bool {
	if len(m) != len(o) {
		return false
	}
	for i := 0; i < len(m); i++ {
		if !m[i].Equal(o[i]) {
			return false
		}
	}
	return true
}

// Mult computes the multiplication dst := src * matrix (in GF2, where mult is logical and).
// If src is an x-bit vector and dst is a y-bit vector then matrix must have dimension x * y.
func Mult(dst, src BitSet, matrix BitMatrix) error {
	x := src.Length()
	y := dst.Length()

	if len(matrix) != y || matrix[0].Length() != x {
		return fmt.Errorf("bitmatrix.Mult: invalid input")
	}

	out := dst.limbs
	for i := range out {
		out[i] = 0
	}

	for i := 0; i < y; i++ {
		onesCount := 0
		columnLimbs := matrix[i].limbs
		val := uint64(0)
		for j := 0; j < len(src.limbs); j++ {
			val ^= src.limbs[j] & columnLimbs[j]
		}
		onesCount = bits2.OnesCount64(val)
		out[i/64] >>= 1
		out[i/64] |= uint64(onesCount&1) << 63
	}
	out[len(out)-1] >>= 64 - (y % 64)

	return nil
}
