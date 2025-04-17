package transport

import (
	"crypto/rsa"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/ers"
)

type ECDSAKeyExportRequest struct {
	WrappingKey []byte   `json:"wrappingKey"`
	ChainPath   []uint32 `json:"chainPath"`
}

type ECDSAKeyExportResponse struct {
	EncryptedKeyShare  []byte `json:"wrappedKeyShare"`
	EncryptedChainCode []byte `json:"wrappedChainCode"`
	Curve              string `json:"curve"`
	PublicKey          []byte `json:"publicKey"`
}

type ECDSAKeyImportRequest struct {
	KeyID     string `json:"keyID"`
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyShare  []byte `json:"keyShare"`
	ChainCode []byte `json:"chainCode"`
	PublicKey []byte `json:"publicKey"`
}

type ECDSAKeyImportResponse struct {
	KeyID string `json:"keyID"`
}

type ECDSAKeyGenRequest struct {
	Threshold int    `json:"threshold"`
	Curve     string `json:"curve"`
	KeyID     string `json:"keyID"`
}

type ECDSAKeyGenResponse struct {
	KeyID string `json:"keyID"`
}

type ECDSAPublicKeyRequest struct {
	ChainPath []uint32 `json:"chainPath"`
}

type ECDSAPublicKeyResponse struct {
	Curve     string `json:"curve"`
	PublicKey []byte `json:"publicKey"`
}

type ECDSAChainCodeRequest struct {
	ChainPath []uint32 `json:"chainPath"`
}

type ECDSAChainCodeResponse struct {
	ChainCode []byte `json:"chainCode"`
}

type ECDSAXPubResponse struct {
	XPub string `json:"xPub"`
}

type ECDSAXPubRequest struct {
	ChainPath []uint32 `json:"chainPath"`
}

type ECDSAPresigGenResponse struct {
	IDs []string `json:"ids"`
}

type ECDSASignRequest struct {
	ChainPath   []uint32 `json:"chainPath"`
	MessageHash []byte   `json:"messageHash"`
}

type ECDSASignWithPresigRequest struct {
	ChainPath      []uint32 `json:"chainPath"`
	MessageHash    []byte   `json:"messageHash"`
	PresignatureID string   `json:"presignatureId"`
}

type ECDSASignResponse struct {
	PresignatureID string `json:"presignatureId"`
	Curve          string `json:"curve"`
	PlayerIndex    int    `json:"playerIndex"`
	Threshold      int    `json:"threshold"`
	Sharing        string `json:"sharing"`
	SShare         []byte `json:"sShare"`
	R              []byte `json:"r"`
	PublicKey      []byte `json:"publicKey"`
}

type ECDSABackupResponse struct {
	ShareBackup []byte `json:"backup"`
}

type ECDSARestoreRequest struct {
	ShareBackup []byte `json:"backup"`
}

type ECDSARestoreResponse struct {
	KeyID string `json:"keyID"`
}

type ECDSARecoveryInfoRequest struct {
	ERSPublicKey      rsa.PublicKey `json:"ersPublicKey"`
	Label             []byte        `json:"label"`
	OutputPlayerIndex int           `json:"outputPlayerIndex"`
}

type ECDSARecoveryInfoResponse struct {
	RecoveryInfos []ers.PartialRecoveryData `json:"recoveryInfos"`
}

type ECDSABIP32GenSeedRequest struct {
	Threshold int `json:"threshold"`
}

type ECDSABIP32GenSeedResponse struct {
	SeedID string `json:"seedID"`
}

type ECDSABIP32DeriveFromSeedRequest struct {
	SeedID string `json:"seedID"`
}

type ECDSABIP32DeriveFromSeedResponse struct {
	KeyID string `json:"keyID"`
}

type ECDSABIP32DeriveFromKeyRequest struct {
	ParentKeyID      string `json:"parentKeyID"`
	ChainPathElement uint32 `json:"chainPathElement"`
}

type ECDSABIP32DeriveFromKeyResponse struct {
	ChildKeyID string `json:"childKeyID"`
}

type ECDSABIP32ConvertKeyRequest struct {
	KeyID string `json:"keyID"`
}

type ECDSABIP32ConvertKeyResponse struct {
	KeyID string `json:"keyID"`
}

type ECDSABIP32ImportSeedRequest struct {
	Threshold   int    `json:"threshold"`
	SeedShare   []byte `json:"seedShare"`
	SeedWitness []byte `json:"seedWitness"`
}

type ECDSABIP32ImportSeedResponse struct {
	SeedID string `json:"seedID"`
}

type ECDSABIP32ExportSeedRequest struct {
	WrappingKey []byte `json:"wrappingKey"`
}

type ECDSABIP32ExportSeedResponse struct {
	EncryptedSeedShare []byte `json:"wrappedSeedShare"`
	SeedWitness        []byte `json:"seedWitness"`
}

type ECDSABIP32InfoResponse struct {
	KeyType     string   `json:"keyType"`
	ChainPath   []uint32 `json:"chainPath"`
	ParentKeyID string   `json:"parentKeyID"`
}
