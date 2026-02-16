package ers

const (
	// Version is used by external recovery services to know how to validate and recover.
	// Must be bumped whenever the validate procedure or the recover procedure changes.
	//
	// Version:
	// 1: Initial version
	// 2: Include zero-knowledge proofs in recovery data; and include additional context (player count, threshold,
	//    sharing type, curve name, player index, master chain code) in the call to the hash function.
	// 3: Removed PlayerCount and changed KeyShareCommitments from slice to map.
	Version = "3"

	N = 80
	K = N / 2
)

type PartialRecoveryData struct {
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

type RecoveryData struct {
	Version             string                `json:"version"`
	PartialRecoveryData []PartialRecoveryData `json:"recovery_data"`
}

type ECDSAAuxDataPublic struct {
	Algorithm string `json:"algorithm"`
}

type ECDSAAuxDataPrivate struct {
	MasterChainCode []byte `json:"master_chain_code"`
}

type SchnorrAuxDataPublic struct {
	Algorithm string `json:"algorithm"`
}

type SchnorrAuxDataPrivate struct {
	MasterChainCode []byte `json:"master_chain_code"`
}

type BLSAuxDataPublic struct {
	Algorithm string `json:"algorithm"`
}

type BLSAuxDataPrivate struct {
	MasterChainCode []byte `json:"master_chain_code"`
}
