package ers

import (
	"encoding/json"
	"fmt"
	"github.com/palisadeinc/mpc-recovery/math"
)

func recoverPrivateKeyV3(decryptor Decryptor, ersLabel, recoveryData []byte) (ellipticCurve string, privateKey []byte, masterChainCode []byte, err error) {
	recData, err := parseRecoveryDataV3(recoveryData)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error parsing recovery data: %s", err)
	}

	// Recover private key

	keyShares, publicKey, err := recoverKeySharesV3(recData, decryptor, ersLabel)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error recovering key shares: %s", err)
	}

	sharingType := recData.PartialRecoveryData[0].SharingType
	threshold := recData.PartialRecoveryData[0].Threshold
	reconstructedPrivateKey, err := reconstruct(keyShares, sharingType, threshold)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error reconstructing private key: %s", err)
	}

	if !publicKey.Curve().G().Mul(reconstructedPrivateKey).Equals(publicKey) {
		return "", nil, nil, fmt.Errorf("recovery data is corrupt: reconstructed the wrong private key")
	}

	// Recover master chain code

	privateAuxEnc := recData.PartialRecoveryData[0].AuxDataPrivateEncrypted
	privateAuxWrappedEncKey := recData.PartialRecoveryData[0].AuxDataWrappedEncryptionKey
	privateAuxData, err := recoverWrappedData(privateAuxEnc, privateAuxWrappedEncKey, decryptor, ersLabel)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error recovering private auxiliary data: %w", err)
	}
	var auxPriv struct {
		MasterChainCode []byte `json:"master_chain_code"`
	}
	err = json.Unmarshal(privateAuxData, &auxPriv)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error recovering master chain code: %w", err)
	}

	return publicKey.Curve().Impl().Params().Name, reconstructedPrivateKey.Encode(), auxPriv.MasterChainCode, nil

}

func parseRecoveryDataV3(encodedRecoveryData []byte) (*recoveryDataV3, error) {
	var recData recoveryDataV3
	err := json.Unmarshal(encodedRecoveryData, &recData)
	if err != nil {
		return nil, err
	}
	return &recData, nil
}

func recoverKeySharesV3(recoveryData *recoveryDataV3, decryptor Decryptor, label []byte) (map[int]math.Scalar, math.Point, error) {
	keyParts, err := validateV3(*recoveryData, nil, nil, nil)
	if err != nil {
		return nil, math.Point{}, fmt.Errorf("invalid recovery data: %w", err)
	}

	curve, err := math.NewCurve(recoveryData.PartialRecoveryData[0].Curve)
	if err != nil {
		return nil, math.Point{}, err
	}

	publicKey, err := curve.DecodePoint(recoveryData.PartialRecoveryData[0].PublicKey)
	if err != nil {
		return nil, math.Point{}, fmt.Errorf("invalid public key: %w", err)
	}

	keyShares, err := recoverKeyShares(curve, keyParts, decryptor, label)
	if err != nil {
		return nil, math.Point{}, err
	}

	return keyShares, publicKey, nil
}
