package models

type KeyAlgorithm string

const (
	KeyAlgorithmSECP256K1 KeyAlgorithm = "SECP256K1"
	KeyAlgorithmED25519   KeyAlgorithm = "ED25519"
)

type RecoveryDataObject struct {
	Index                         uint   `json:"index"`
	RecoveryPublicKeyHex          string `json:"recoveryPublicKeyHex"`
	PartialRecoveryDataBase64     string `json:"partialRecoveryDataHex"`
	WalletRootPublicKeyPkixBase64 string `json:"walletRootPublicKeyPkixBase64"`
	WalletPublicKeyBase64         string `json:"walletPublicKeyBase64"`
}
