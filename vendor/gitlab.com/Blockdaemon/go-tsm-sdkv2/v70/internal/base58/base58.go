package base58

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

var (
	bigIntermediateRadix = big.NewInt(430804206899405824) // 58**10
	alphabet             = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	b58table             = [256]byte{
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 0, 1, 2, 3, 4, 5, 6,
		7, 8, 255, 255, 255, 255, 255, 255,
		255, 9, 10, 11, 12, 13, 14, 15,
		16, 255, 17, 18, 19, 20, 21, 255,
		22, 23, 24, 25, 26, 27, 28, 29,
		30, 31, 32, 255, 255, 255, 255, 255,
		255, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 255, 44, 45, 46,
		47, 48, 49, 50, 51, 52, 53, 54,
		55, 56, 57, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255,
	}
)

func Encode(input []byte) string {
	output := make([]byte, 0)
	num := new(big.Int).SetBytes(input)
	mod := new(big.Int)

	var primitiveNum int64
	for num.Sign() > 0 {
		num.DivMod(num, bigIntermediateRadix, mod)
		primitiveNum = mod.Int64()
		for i := 0; (num.Sign() > 0 || primitiveNum > 0) && i < 10; i++ {
			output = append(output, alphabet[primitiveNum%58])
			primitiveNum /= 58
		}
	}

	for i := 0; i < len(input) && input[i] == 0; i++ {
		output = append(output, alphabet[0])
	}

	for i := 0; i < len(output)/2; i++ {
		output[i], output[len(output)-1-i] = output[len(output)-1-i], output[i]
	}

	return string(output)
}

func Decode(input string) ([]byte, error) {
	result := big.NewInt(0)
	tmpBig := new(big.Int)

	for i := 0; i < len(input); {
		var a, m int64 = 0, 58
		for f := true; i < len(input) && (f || i%10 != 0); i++ {
			tmp := b58table[input[i]]
			if tmp == 255 {
				return nil, fmt.Errorf("invalid Base58 input string at character \"%c\", position %d", input[i], i)
			}
			a = a*58 + int64(tmp)
			if !f {
				m *= 58
			}
			f = false
		}

		result.Mul(result, tmpBig.SetInt64(m))
		result.Add(result, tmpBig.SetInt64(a))
	}

	tmpBytes := result.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(input); numZeros++ {
		if input[numZeros] != '1' {
			break
		}
	}
	output := make([]byte, numZeros+len(tmpBytes))
	copy(output[numZeros:], tmpBytes)

	return output, nil
}

// ErrChecksum indicates that the checksum of a check-encoded string does not verify against the checksum.
var ErrChecksum = errors.New("checksum error")

// ErrInvalidFormat indicates that the check-encoded string has an invalid format.
var ErrInvalidFormat = errors.New("invalid format: version and/or checksum bytes missing")

// CheckEncode prepends a version byte and appends a four byte checksum.
func CheckEncode(input []byte, version byte) string {
	b := make([]byte, 0, 1+len(input)+4)
	b = append(b, version)
	b = append(b, input[:]...)
	checksum := computeChecksum(b)
	b = append(b, checksum[:]...)
	return Encode(b)
}

// CheckDecode decodes a string that was encoded with CheckEncode and verifies the checksum.
func CheckDecode(input string) (result []byte, version byte, err error) {
	decoded, err := Decode(input)
	if err != nil {
		return nil, 0, err
	}
	if len(decoded) < 5 {
		return nil, 0, ErrInvalidFormat
	}
	version = decoded[0]
	var checksum [4]byte
	copy(checksum[:], decoded[len(decoded)-4:])
	if computeChecksum(decoded[:len(decoded)-4]) != checksum {
		return nil, 0, ErrChecksum
	}
	payload := decoded[1 : len(decoded)-4]
	result = append(result, payload...)
	return result, version, nil
}

func computeChecksum(input []byte) (checksum [4]byte) {
	h := sha256.Sum256(input)
	h2 := sha256.Sum256(h[:])
	copy(checksum[:], h2[:4])
	return checksum
}
