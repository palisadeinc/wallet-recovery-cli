package ers

import (
	"encoding/json"
	"fmt"
)

const (
	RecoveryDataVersion1 = "1.0.0"
	RecoveryDataVersion2 = "2"
	RecoveryDataVersion3 = "3"
)

const (
	n = 80
	k = n / 2
)

const (
	additive       string = "additive"
	multiplicative        = "multiplicative"
	shamir                = "shamir"
)

type recoveryDataV1 struct {
	PublicKey          []byte                `json:"public_key"`
	Version            string                `json:"version"`
	SharingType        string                `json:"sharing_type"`
	Threshold          int                   `json:"threshold"`
	KeyParts           []recoveryDataKeyPart `json:"key_parts"`
	MasterChainCode    []byte                `json:"master_chain_code"`
	MasterChainCodeKey []byte                `json:"master_chain_code_key"`
}

type recoveryDataKeyPart struct {
	PartCommitment  []byte         `json:"commitment"`
	Values          map[int][]byte `json:"values"`
	EncryptedValues map[int][]byte `json:"encrypted_values"`
}

type recoveryDataV2 struct {
	Version             string                  `json:"version"`
	PartialRecoveryData []partialRecoveryDataV2 `json:"recovery_data"`
}

type partialRecoveryDataV2 struct {
	Version                     string   `json:"version"`
	PlayerIndex                 int      `json:"player_index"`
	PlayerCount                 int      `json:"player_count"`
	Threshold                   int      `json:"threshold"`
	SharingType                 string   `json:"sharing_type"`
	Curve                       string   `json:"curve"`
	PublicKey                   []byte   `json:"public_key"`
	Es                          [][]byte `json:"es"`
	Ys                          [][]byte `json:"ys"`
	Vs                          [][]byte `json:"vs"`
	Rs                          [][]byte `json:"rs"`
	KeyShareCommitments         [][]byte `json:"key_share_commitments"`
	Combination                 []int    `json:"combination"`
	Nonce                       []byte   `json:"nonce"`
	AuxDataPublic               []byte   `json:"aux_data_public"`
	AuxDataPrivateEncrypted     []byte   `json:"aux_data_private_encrypted"`
	AuxDataWrappedEncryptionKey []byte   `json:"aux_data_wrapped_encryption_key"`
}

type recoveryDataV3 struct {
	Version             string                  `json:"version"`
	PartialRecoveryData []partialRecoveryDataV3 `json:"recovery_data"`
}

type partialRecoveryDataV3 struct {
	Version                     string         `json:"version"`
	PlayerIndex                 int            `json:"player_index"`
	Threshold                   int            `json:"threshold"`
	SharingType                 string         `json:"sharing_type"`
	Curve                       string         `json:"curve"`
	PublicKey                   []byte         `json:"public_key"`
	Es                          [][]byte       `json:"es"`
	Ys                          [][]byte       `json:"ys"`
	Vs                          [][]byte       `json:"vs"`
	Rs                          [][]byte       `json:"rs"`
	KeyShareCommitments         map[int][]byte `json:"key_share_commitments"`
	Combination                 []int          `json:"combination"`
	Nonce                       []byte         `json:"nonce"`
	AuxDataPublic               []byte         `json:"aux_data_public"`
	AuxDataPrivateEncrypted     []byte         `json:"aux_data_private_encrypted"`
	AuxDataWrappedEncryptionKey []byte         `json:"aux_data_wrapped_encryption_key"`
}

func getVersion(encodedRecoveryData []byte) (string, error) {
	var p struct {
		Version string `json:"version"`
	}
	err := json.Unmarshal(encodedRecoveryData, &p)
	if err != nil {
		return "", err
	}

	switch p.Version {
	case RecoveryDataVersion1, RecoveryDataVersion2, RecoveryDataVersion3:
		return p.Version, nil
	default:
		return "", fmt.Errorf("invalid recovery data version: %s", p.Version)
	}
}
