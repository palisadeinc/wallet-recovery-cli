package ers

import (
	"encoding/binary"
	"golang.org/x/crypto/blake2b"
	"io"
	"math/big"
)

type ContextData struct {
	RecoveryDataVersion         string
	PlayerCount                 int // Only for V2
	Threshold                   int
	SharingType                 string
	CurveName                   string
	PlayerIndex                 int
	Nonce                       []byte
	AuxDataPublic               []byte
	AuxDataPrivateEncrypted     []byte
	AuxDataWrappedEncryptionKey []byte
}

// This is only used by V2
func (c ContextData) toBytes() []byte {
	b := make([]byte, 4)
	elmCount := 10
	binary.BigEndian.PutUint32(b, uint32(elmCount))

	b = addString(b, c.RecoveryDataVersion)
	b = addInt(b, c.PlayerCount)
	b = addInt(b, c.Threshold)
	b = addString(b, c.SharingType)
	b = addString(b, c.CurveName)
	b = addInt(b, c.PlayerIndex)
	b = addBytes(b, c.Nonce)
	b = addBytes(b, c.AuxDataPublic)
	b = addBytes(b, c.AuxDataPrivateEncrypted)
	b = addBytes(b, c.AuxDataWrappedEncryptionKey)

	return b
}

func addString(data []byte, s string) []byte {
	return addBytes(data, []byte(s))
}

func addInt(data []byte, i int) []byte {
	iBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(iBytes, uint32(i))
	return addBytes(data, iBytes)
}

func addBytes(data, elm []byte) []byte {
	lenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(len(elm)))
	data = append(data, lenBytes...)
	data = append(data, elm...)
	return data
}

// Used from V3
func (c ContextData) writeTo(w io.Writer) {
	var b [4]byte
	elmCount := 9
	binary.BigEndian.PutUint32(b[:], uint32(elmCount))
	_, _ = w.Write(b[:])

	writeString(w, c.RecoveryDataVersion)
	writeInt(w, c.Threshold)
	writeString(w, c.SharingType)
	writeString(w, c.CurveName)
	writeInt(w, c.PlayerIndex)
	writeBytes(w, c.Nonce)
	writeBytes(w, c.AuxDataPublic)
	writeBytes(w, c.AuxDataPrivateEncrypted)
	writeBytes(w, c.AuxDataWrappedEncryptionKey)
}

func writeInt(w io.Writer, i int) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(i))
	writeBytes(w, b[:])
}

func writeString(w io.Writer, s string) {
	writeBytes(w, []byte(s))
}

func writeBytes(w io.Writer, elm []byte) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(elm)))
	_, _ = w.Write(b[:])
	_, _ = w.Write(elm)
}

func hashToCombination(version string, n, k int, publicKey []byte, eis, yis [][]byte, keyShareCommitment []byte, ctxData ContextData) []int {
	noOfCombinations := new(big.Int).Binomial(int64(n), int64(k))

	x, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	writeBytes(x, publicKey)
	if version == RecoveryDataVersion2 {
		writeBytes(x, ctxData.toBytes())
	} else {
		ctxData.writeTo(x)
	}

	for i := 0; i < n; i++ {
		writeBytes(x, eis[i])
	}
	for i := 0; i < k; i++ {
		writeBytes(x, yis[i])
	}
	writeBytes(x, keyShareCommitment)

	randomBytes := make([]byte, (noOfCombinations.BitLen()+128)/8)
	_, _ = x.Read(randomBytes)
	combinationIndex := new(big.Int).SetBytes(randomBytes)

	return combination(n, k, combinationIndex)
}

var zero = big.NewInt(0)

// Combination maps a number to one of the "n choose k" possible combinations. If the number is larger than the number
// of combinations it is reduced modulo the number of combinations first. The returned combination will always have the
// lowest number first.
func combination(n, k int, combinationNumber *big.Int) []int {

	nChooseK := new(big.Int).Binomial(int64(n), int64(k))
	combinationNumber = new(big.Int).Mod(combinationNumber, nChooseK)

	res := make([]int, k)
	c := new(big.Int).Set(zero)
	for i := k; i > 0; i-- {
		combinationNumber.Sub(combinationNumber, c)
		for j := n - 1; j >= 0; j-- {
			c.Set(new(big.Int).Binomial(int64(j), int64(i)))
			if c.Cmp(combinationNumber) <= 0 {
				res[i-1] = j
				break
			}
		}
	}

	return res
}
