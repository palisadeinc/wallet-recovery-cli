package random

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/big"
	"sync"
	"unsafe"
)

const (
	letters           = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	letterIndexBits   = 6
	letterIndexMask   = 1<<letterIndexBits - 1
	letterIndexMax    = 63 / letterIndexBits
	maxPoolBufferSize = (521 + 7) / 8
)

var Reader = rand.Reader

var maxIntPlusOne = new(big.Int).Add(big.NewInt(math.MaxInt), big.NewInt(1))

var bufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, maxPoolBufferSize)
		return &b
	},
}

func Bytes(size int) []byte {
	return BytesFromReader(Reader, size)
}

func Int() int {
	return IntFromReader(Reader)
}

func BigInt(n *big.Int) *big.Int {
	return BigIntFromReader(Reader, n)
}

func String(length int) string {
	return StringFromReader(Reader, length)
}

func BytesFromReader(reader io.Reader, size int) []byte {
	b := make([]byte, size)
	SetBytesFromReader(b, reader)
	return b
}

func IntFromReader(reader io.Reader) int {
	r := new(big.Int)
	SetBigIntFromReader(r, reader, maxIntPlusOne)
	return int(r.Int64())
}

func BigIntFromReader(reader io.Reader, n *big.Int) *big.Int {
	r := new(big.Int)
	SetBigIntFromReader(r, reader, n)
	return r
}

func StringFromReader(reader io.Reader, length int) string {
	if length == 0 {
		return ""
	}
	b := make([]byte, length)
	for i, cache, remain := length-1, int64FromReader(reader), letterIndexMax; i >= 0; {
		if remain == 0 {
			cache, remain = int64FromReader(reader), letterIndexMax
		}
		if idx := int(cache & letterIndexMask); idx < len(letters) {
			b[i] = letters[idx]
			i--
		}
		cache >>= letterIndexBits
		remain--
	}

	// #nosec G103
	return *(*string)(unsafe.Pointer(&b))
}

func SetBytesFromReader(dst []byte, reader io.Reader) {
	_, err := reader.Read(dst)
	if err != nil {
		panic(readerError(err))
	}
}

func SetBigIntFromReader(dst *big.Int, reader io.Reader, n *big.Int) {
	if n.Sign() <= 0 {
		panic("max is zero or negative")
	}
	dst.Sub(n, dst.SetUint64(1))
	bitLen := dst.BitLen()
	if bitLen == 0 {
		return
	}
	k := (bitLen + 7) / 8
	b := uint(bitLen % 8)
	if b == 0 {
		b = 8
	}

	var bufferFromPool *[]byte
	var buffer []byte
	if k <= maxPoolBufferSize {
		bufferFromPool = bufferPool.Get().(*[]byte)
		buffer = (*bufferFromPool)[:k]
	} else {
		buffer = make([]byte, k)
	}

	for {
		_, err := io.ReadFull(reader, buffer)
		if err != nil {
			panic(readerError(err))
		}
		buffer[0] &= uint8(int(1<<b) - 1)
		dst.SetBytes(buffer)
		if dst.Cmp(n) < 0 {
			break
		}
	}

	if bufferFromPool != nil {
		bufferPool.Put(bufferFromPool)
	}
}

func int64FromReader(reader io.Reader) int64 {
	var x int64
	err := binary.Read(reader, binary.BigEndian, &x)
	if err != nil {
		panic(readerError(err))
	}
	return x
}

func readerError(err error) string {
	return fmt.Sprintf("read failed: %s", err)
}
