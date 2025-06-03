package utils

import (
	"encoding/hex"

	"github.com/ethereum/go-ethereum/crypto"
)

func GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes []byte) (string, error) {
	pkey, err := crypto.HexToECDSA(hex.EncodeToString(privateKeyBytes))
	if err != nil {
		return "", err
	}
	return crypto.PubkeyToAddress(pkey.PublicKey).Hex(), nil
}
