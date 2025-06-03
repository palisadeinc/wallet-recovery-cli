package transport

import (
	"crypto/rsa"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ers"
)

type SchnorrKeyGenRequest struct {
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyID     string `json:"keyID"`
}

type SchnorrKeyGenResponse struct {
	KeyID string `json:"keyID"`
}

type SchnorrPublicKeyRequest struct {
	ChainPath []uint32 `json:"chainPath"`
}

type SchnorrPublicKeyResponse struct {
	Curve     string `json:"curve"`
	PublicKey []byte `json:"publicKey"`
}

type SchnorrChainCodeRequest struct {
	ChainPath []uint32 `json:"chainPath"`
}

type SchnorrChainCodeResponse struct {
	ChainCode []byte `json:"chainCode"`
}

type SchnorrSignRequest struct {
	ChainPath []uint32 `json:"chainPath"`
	Message   []byte   `json:"message"`
}

type SchnorrPresigGenResponse struct {
	IDs []string `json:"ids"`
}

type SchnorrSignWithPresigRequest struct {
	ChainPath      []uint32 `json:"chainPath"`
	Message        []byte   `json:"message"`
	PresignatureID string   `json:"presignatureId"`
}

type SchnorrSignResponse struct {
	PresignatureID string `json:"presignatureId"`
	Curve          string `json:"curve"`
	Threshold      int    `json:"threshold"`
	PlayerIndex    int    `json:"playerIndex"`
	Sharing        string `json:"sharing"`
	SShare         []byte `json:"sShare"`
	R              []byte `json:"r"`
	PublicKey      []byte `json:"publicKey"`
}

type SchnorrRecoveryInfoRequest struct {
	ERSPublicKey      rsa.PublicKey `json:"ersPublicKey"`
	Label             []byte        `json:"label"`
	OutputPlayerIndex int           `json:"outputPlayerIndex"`
}

type SchnorrRecoveryInfoResponse struct {
	RecoveryInfos []ers.PartialRecoveryData `json:"recoveryInfos"`
}

type SchnorrBackupResponse struct {
	ShareBackup []byte `json:"backup"`
}

type SchnorrRestoreRequest struct {
	ShareBackup []byte `json:"backup"`
}

type SchnorrRestoreResponse struct {
	KeyID string `json:"keyID"`
}

type SchnorrKeyExportRequest struct {
	WrappingKey []byte   `json:"wrappingKey"`
	ChainPath   []uint32 `json:"chainPath"`
}

type SchnorrKeyExportResponse struct {
	EncryptedKeyShare  []byte `json:"wrappedKeyShare"`
	EncryptedChainCode []byte `json:"wrappedChainCode"`
	Curve              string `json:"curve"`
	PublicKey          []byte `json:"publicKey"`
}

type SchnorrKeyImportRequest struct {
	KeyID     string `json:"keyID"`
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyShare  []byte `json:"keyShare"`
	ChainCode []byte `json:"chainCode"`
	PublicKey []byte `json:"publicKey"`
}

type SchnorrKeyImportResponse struct {
	KeyID string `json:"keyID"`
}

type SchnorrKeyCopyRequest struct {
	KeyID     string `json:"keyID"`
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
}

type SchnorrKeyCopyResponse struct {
	KeyID string `json:"keyID"`
}
