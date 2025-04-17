package models

type RecoveryDataObject struct {
	Index                         uint   `json:"index"`
	RecoveryPublicKeyHex          string `json:"recoveryPublicKeyHex"`
	PartialRecoveryDataBase64     string `json:"partialRecoveryDataHex"`
	WalletRootPublicKeyPkixBase64 string `json:"walletRootPublicKeyPkixBase64"`
	WalletPublicKeyBase64         string `json:"walletPublicKeyBase64"`
}
