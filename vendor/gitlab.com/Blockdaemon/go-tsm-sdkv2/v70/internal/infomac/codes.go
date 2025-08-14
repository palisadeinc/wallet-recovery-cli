package infomac

import (
	"bufio"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/bits"
	"strconv"
	"strings"
)

func NewLinearCode(dimension, minDist int) LinearSystematicCode {
	if minDist <= 40 && dimension <= 128 {
		tagGeneratorMatrix, err := readMatrixFromString(bch128x134)
		if err != nil {
			panic(err)
		}
		code := newLinearSystematicCode(262, 128, 40, tagGeneratorMatrix)
		code = code.Shorten(128 - dimension)
		return code

	}

	if minDist <= 83 && dimension <= 211 {
		tagGeneratorMatrix, err := readMatrixFromString(bch511x211)
		if err != nil {
			panic(err)
		}
		code := newLinearSystematicCode(511, 211, 83, tagGeneratorMatrix)
		code = code.Shorten(211 - dimension)
		return code
	}

	if minDist <= 83 && dimension <= 1023 {
		tagGeneratorMatrix, err := readMatrixFromString(bch1023x648)
		if err != nil {
			panic(err)
		}
		code := newLinearSystematicCode(1023, 648, 83, tagGeneratorMatrix)
		code = code.Shorten(648 - dimension)
		return code
	}

	panic(fmt.Sprintf("parameters not currently supported (dimension = %d, minimum distance = %d", dimension, minDist))

}

// Converts binary matrix from string representation to bit set
//
// The string format is like this (3 rows, 5 columns):
//
//	3 5
//	1 0 1 1 0
//	0 0 0 1 0
//	1 1 1 0 1
//
// The returned matrix is in row-major format.
func readMatrixFromString(mStr string) (bits.BitSet, error) {
	scanner := bufio.NewScanner(strings.NewReader(mStr))
	b := scanner.Scan()
	if !b {
		return bits.BitSet{}, ErrBadFormat
	}
	words := strings.Fields(scanner.Text())
	if len(words) != 2 {
		return bits.BitSet{}, ErrBadFormat
	}
	rows, err := strconv.Atoi(words[0])
	if err != nil {
		return bits.BitSet{}, ErrBadFormat
	}
	cols, err := strconv.Atoi(words[1])
	if err != nil {
		return bits.BitSet{}, ErrBadFormat
	}
	if cols <= 0 || rows <= 0 {
		return bits.BitSet{}, ErrBadFormat
	}

	res := bits.NewZeroSet(rows * cols)

	for r := 0; r < rows; r++ {
		b := scanner.Scan()
		if !b {
			return bits.BitSet{}, ErrBadFormat
		}
		rowStr := strings.Fields(scanner.Text())
		if len(rowStr) != cols {
			return bits.BitSet{}, ErrBadFormat
		}

		for c := 0; c < cols; c++ {

			b, err := strconv.Atoi(rowStr[c])
			if err != nil || (b != 0 && b != 1) {
				return bits.BitSet{}, ErrBadFormat
			}

			res.Assign(r*cols+c, bits.Bit(b))

		}

	}

	if scanner.Scan() {
		return bits.BitSet{}, ErrBadFormat
	}

	return res, nil
}

var ErrBadFormat = fmt.Errorf("bad format")

// newLinearSystematicCode constructs an [n,k,d] code from a tag generator matrix in row-major form.
// As the code is systematic, only the tag generator matrix is needed for generating the tag (aka parity) bits.
// The tag generator matrix must have dimensions k x (n-k), meaning that the bit length of the matrix must be k*(n-k).
// Tag generator matrix must be in row-major format, meaning that the first row is tagGeneratorMatrix.Subset(0,n-k),
// and so forth.
func newLinearSystematicCode(length, dimension, minDistance int, tagGeneratorMatrix bits.BitSet) LinearSystematicCode {
	if tagGeneratorMatrix.Length() != dimension*(length-dimension) {
		panic(fmt.Sprintf("bad dimension (expected %d, got %d)", dimension*(length-dimension), tagGeneratorMatrix.Length()))
	}

	return LinearSystematicCode{
		TagGeneratorMatrix: tagGeneratorMatrix,
		n:                  length,
		k:                  dimension,
		d:                  minDistance,
	}

}

type LinearSystematicCode struct {
	TagGeneratorMatrix bits.BitSet
	k, n, d            int
}

func (c LinearSystematicCode) GetDimension() int {
	return c.k
}

func (c LinearSystematicCode) GetLength() int {
	return c.n
}

func (c LinearSystematicCode) GetMinDistance() int {
	return c.d
}

// Encode a message into a codeword.
// The first bits of the codeword equals the message vector.
func (c LinearSystematicCode) Encode(msg bits.BitSet) (codeword bits.BitSet) {
	if msg.Length() != c.k {
		panic(fmt.Sprintf("bad message length (expected %d, got %d)", c.k, msg.Length()))
	}

	parityBits, err := matrixMul(msg, c.TagGeneratorMatrix)
	if err != nil {
		panic(err)
	}

	return bits.Concat(msg, parityBits)

}

func (c LinearSystematicCode) String() string {
	return fmt.Sprintf("[%d,%d,%d]", c.n, c.k, c.d)
}

// Shorten returns the shortened code [n-s, k-s, d].
func (c LinearSystematicCode) Shorten(s int) LinearSystematicCode {
	if s < 0 || s >= c.k {
		panic(fmt.Sprintln("can only shorten code to dimension smaller than original dimension", s))
	}

	// Remove top s rows from the original tag generator matrix.
	rowSize := c.n - c.k
	shortenedTagGeneratorMatrix := c.TagGeneratorMatrix.Subset(s*rowSize, c.TagGeneratorMatrix.Length())

	return newLinearSystematicCode(c.n-s, c.k-s, c.d, shortenedTagGeneratorMatrix)

}

// matrixMul computes y = Mx.
// The matrix M is supposed to be in row-major form, the length of M must be
// a multiple of len(x), and the output y will be a bit set of of length len(M) / len(x).
func matrixMul(x bits.BitSet, M bits.BitSet) (bits.BitSet, error) {
	if M.Length()%x.Length() != 0 {
		return bits.BitSet{}, fmt.Errorf("invalid input")
	}
	rows := x.Length()
	cols := M.Length() / rows
	res := bits.NewZeroSet(cols)

	// row-major
	get := func(r, c int) bits.Bit {
		return M.Get(r*cols + c)
	}

	for c := 0; c < cols; c++ {
		res.Assign(c, x.Get(0)&get(0, c))
		for r := 1; r < rows; r++ {
			w := x.Get(r) & get(r, c)
			res.Assign(c, res.Get(c)^w)
		}
	}

	return res, nil
}

// MinDistEncoder encodes bit strings of arbitrary length. It ensures a certain minimum hamming distance between any
// two encodings of different bit strings.
type MinDistEncoder interface {
	GetMinimumDistance() int
	GetEncodingSize(msg bits.BitSet) int
	Encode(msg bits.BitSet) (encoding bits.BitSet)
}

type BlockEncoder struct {
	code LinearSystematicCode
}

func NewBlockEncoder(bitLength, securityLevel int) BlockEncoder {
	dimension := bitLength

	if securityLevel <= 40 {

		// For 40-bit security or less we currently only have one code, so we repeat this.
		if dimension > 128 {
			dimension = 128
		}

	} else if securityLevel <= 80 {

		// For 80-bit security we have two codes. But using a larger code than than BCH(511, 211) causes the clear-text
		// matrix multiplication to take longer than the additional MPC operations required with repeated use of a
		// smaller code.
		if dimension > 211 {
			dimension = 211
		}
	}

	code := NewLinearCode(dimension, securityLevel)
	return NewBlockEncoderFromCode(code)
}

func NewBlockEncoderFromCode(code LinearSystematicCode) BlockEncoder {
	return BlockEncoder{
		code: code,
	}
}

func (e BlockEncoder) GetEncodingSize(msg bits.BitSet) int {
	blocks := msg.Length() / e.code.GetDimension()
	encodingSize := blocks * e.code.GetLength()

	restLength := msg.Length() % e.code.GetDimension()
	if restLength > 0 {
		shortenedCodeLength := e.code.GetLength() - e.code.GetDimension() + restLength
		encodingSize += shortenedCodeLength
	}

	return encodingSize

}

func (e BlockEncoder) GetMinimumDistance() int {
	return e.code.GetMinDistance()
}

func (e BlockEncoder) Encode(msg bits.BitSet) bits.BitSet {
	result := bits.BitSet{}
	dimension := e.code.GetDimension()
	blocks := msg.Length() / dimension
	for i := 0; i < blocks; i++ {
		block := msg.Subset(i*dimension, (i+1)*dimension)
		encoded := e.code.Encode(block)
		result = bits.Concat(result, encoded)
	}

	rest := msg.Subset(blocks*dimension, msg.Length())
	if rest.Length() > 0 {
		shortenedCode := e.code.Shorten(dimension - rest.Length())
		encoded := shortenedCode.Encode(rest)
		result = bits.Concat(result, encoded)
	}

	return result

}
