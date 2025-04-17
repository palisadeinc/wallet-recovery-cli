package ers

import (
	"crypto/rsa"
	"crypto/sha256"
)

type RSADecryptor struct {
	privateKey *rsa.PrivateKey
}

func (r RSADecryptor) Decrypt(ciphertext, label []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), nil, r.privateKey, ciphertext, label)
}

func NewRSADecryptor(privateKey *rsa.PrivateKey) Decryptor {
	return RSADecryptor{privateKey: privateKey}
}
