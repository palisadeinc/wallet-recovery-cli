package secretshare

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
)

type AESKeyShare struct {
	Share    []byte // simple xor shares of key
	Checksum []byte // first three bytes of AES_key(0x01, 0x01, 0x01,..)
}

type HMACKeyShare struct {
	Share    []byte // simple xor shares of key
	Checksum []byte // first three bytes of SHA256("BuilderVault HMAC Key" || key)
}

func (s AESKeyShare) KeyLength() int {
	return len(s.Share)
}

func (s HMACKeyShare) KeyLength() int {
	return len(s.Share)
}

const (
	AESChecksumLength  = 3
	HMACChecksumLength = 3

	HMACKeyMinLength = 1
	HMACKeyMaxLength = 256
)

var (
	AESChecksumPlaintext = []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}
	HMACChecksumHeader   = []byte("BuilderVault HMAC Key")
)

func AESSecretShare(players []int, aesKey []byte) (shares map[int]AESKeyShare, err error) {
	if len(players) < 2 || !unique(players) {
		return nil, fmt.Errorf("invalid player list")
	}

	keyLength := len(aesKey)
	if keyLength != 16 && keyLength != 24 && keyLength != 32 {
		return nil, fmt.Errorf("invalid aes key length")
	}

	checksum := ChecksumAES(aesKey)

	shares = make(map[int]AESKeyShare, len(players))

	shares[players[0]] = AESKeyShare{
		Share:    make([]byte, keyLength),
		Checksum: make([]byte, AESChecksumLength),
	}
	copy(shares[players[0]].Share, aesKey)
	copy(shares[players[0]].Checksum, checksum)

	for i := 1; i < len(players); i++ {
		shares[players[i]] = AESKeyShare{
			Share:    random.Bytes(keyLength),
			Checksum: make([]byte, AESChecksumLength),
		}
		copy(shares[players[i]].Checksum, checksum)
		for j := 0; j < len(shares[players[i]].Share); j++ {
			shares[players[0]].Share[j] ^= shares[players[i]].Share[j]
		}
	}

	return shares, nil

}

func AESRecoverSecret(shares map[int]AESKeyShare) (aesKey []byte, err error) {
	if len(shares) < 1 {
		return nil, fmt.Errorf("no shares")
	}

	var checksum []byte

	for _, share := range shares {
		aesKey = make([]byte, len(share.Share))
		if len(aesKey) != 16 && len(aesKey) != 24 && len(aesKey) != 32 {
			return nil, fmt.Errorf("invalid aes key length")
		}
		checksum = make([]byte, AESChecksumLength)
		copy(checksum, share.Checksum)
		if len(checksum) != AESChecksumLength {
			return nil, fmt.Errorf("invalid aes checksum")
		}

		break
	}

	for _, share := range shares {
		if len(aesKey) != len(share.Share) {
			return nil, fmt.Errorf("share length mismatch")
		}
		if !bytes.Equal(checksum, share.Checksum) {
			return nil, fmt.Errorf("checksum mismatch")
		}
		for j := 0; j < len(aesKey); j++ {
			aesKey[j] ^= share.Share[j]
		}
	}

	expectedChecksum := ChecksumAES(aesKey)
	if !bytes.Equal(expectedChecksum, checksum) {
		return nil, fmt.Errorf("invalid checksum")
	}

	return aesKey, nil
}

func HMACSecretShare(players []int, hmacKey []byte) (shares map[int]HMACKeyShare, err error) {
	if len(players) < 2 || !unique(players) {
		return nil, fmt.Errorf("invalid player list")
	}

	keyLength := len(hmacKey)
	if keyLength < HMACKeyMinLength || keyLength > HMACKeyMaxLength {
		return nil, fmt.Errorf("invalid key length")
	}

	checksum := ChecksumHMAC(hmacKey)

	shares = make(map[int]HMACKeyShare, len(players))

	shares[players[0]] = HMACKeyShare{
		Share:    make([]byte, keyLength),
		Checksum: make([]byte, HMACChecksumLength),
	}
	copy(shares[players[0]].Share, hmacKey)
	copy(shares[players[0]].Checksum, checksum)

	for i := 1; i < len(players); i++ {
		shares[players[i]] = HMACKeyShare{
			Share:    random.Bytes(keyLength),
			Checksum: make([]byte, HMACChecksumLength),
		}
		copy(shares[players[i]].Checksum, checksum)
		for j := 0; j < len(shares[players[i]].Share); j++ {
			shares[players[0]].Share[j] ^= shares[players[i]].Share[j]
		}
	}

	return shares, nil

}

func HMACRecoverSecret(shares map[int]HMACKeyShare) (hmacKey []byte, err error) {
	if len(shares) < 1 {
		return nil, fmt.Errorf("no shares")
	}

	var checksum []byte

	for _, share := range shares {
		hmacKey = make([]byte, len(share.Share))
		if len(hmacKey) < HMACKeyMinLength || len(hmacKey) > HMACKeyMaxLength {
			return nil, fmt.Errorf("invalid hmac key length")
		}
		checksum = make([]byte, HMACChecksumLength)
		copy(checksum, share.Checksum)
		if len(checksum) != HMACChecksumLength {
			return nil, fmt.Errorf("invalid hmac checksum")
		}

		break
	}

	for _, share := range shares {
		if len(hmacKey) != len(share.Share) {
			return nil, fmt.Errorf("share length mismatch")
		}
		if !bytes.Equal(checksum, share.Checksum) {
			return nil, fmt.Errorf("checksum mismatch")
		}
		for j := 0; j < len(hmacKey); j++ {
			hmacKey[j] ^= share.Share[j]
		}
	}

	expectedChecksum := ChecksumHMAC(hmacKey)
	if !bytes.Equal(expectedChecksum, checksum) {
		return nil, fmt.Errorf("invalid checksum")
	}

	return hmacKey, nil
}

func ChecksumAES(key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize)
	block.Encrypt(ciphertext, AESChecksumPlaintext)
	expectedChecksum := ciphertext[0:AESChecksumLength]
	return expectedChecksum
}

func ChecksumHMAC(key []byte) []byte {
	data := append(HMACChecksumHeader, key...)
	hash := sha256.New()
	hash.Write(data)
	checksum := hash.Sum(nil)[0:HMACChecksumLength]
	return checksum
}

func unique(players []int) bool {
	m := make(map[int]int, len(players))
	for _, p := range players {
		m[p] = 1
	}
	return len(m) == len(players)
}
