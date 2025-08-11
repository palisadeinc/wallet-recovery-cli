package ers

import (
	"encoding/binary"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/combination"
	"golang.org/x/crypto/blake2b"
	"io"
	"math/big"
)

type RecoveryContext struct {
	RecoveryDataVersion         string
	Threshold                   int
	SharingType                 string
	CurveName                   string
	PlayerIndex                 int
	Nonce                       []byte
	AuxDataPublic               []byte
	AuxDataPrivateEncrypted     []byte
	AuxDataWrappedEncryptionKey []byte
}

func (r RecoveryContext) writeTo(w io.Writer) {
	var b [4]byte
	elmCount := 9
	binary.BigEndian.PutUint32(b[:], uint32(elmCount))
	_, _ = w.Write(b[:])

	writeString(w, r.RecoveryDataVersion)
	writeInt(w, r.Threshold)
	writeString(w, r.SharingType)
	writeString(w, r.CurveName)
	writeInt(w, r.PlayerIndex)
	writeBytes(w, r.Nonce)
	writeBytes(w, r.AuxDataPublic)
	writeBytes(w, r.AuxDataPrivateEncrypted)
	writeBytes(w, r.AuxDataWrappedEncryptionKey)
}

func HashToCombination(publicKey []byte, eis, yis [][]byte, keyShareCommitment []byte, recoveryContext RecoveryContext) []int {
	noOfCombinations := combination.NumberOfCombinations(N, K)

	x, _ := blake2b.NewXOF(blake2b.OutputLengthUnknown, nil)
	writeBytes(x, publicKey)
	recoveryContext.writeTo(x)

	for i := 0; i < N; i++ {
		writeBytes(x, eis[i])
	}
	for i := 0; i < K; i++ {
		writeBytes(x, yis[i])
	}
	writeBytes(x, keyShareCommitment)

	randomBytes := make([]byte, (noOfCombinations.BitLen()+128)/8)
	_, _ = x.Read(randomBytes)
	combinationIndex := new(big.Int).SetBytes(randomBytes)

	return combination.Combination(N, K, combinationIndex)
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
