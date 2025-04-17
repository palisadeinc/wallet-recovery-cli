package ers

import (
	"encoding/json"
	"fmt"
	"github.com/palisadeinc/mpc-recovery/math"
)

func recoverPrivateKeyV1(decryptor Decryptor, ersLabel, recoveryData []byte) (ellipticCurve string, privateKey []byte, masterChainCode []byte, err error) {
	recData, err := parseRecoveryDataV1(recoveryData)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error parsing recovery data: %s", err)
	}

	keyShares, publicKey, err := recoverKeySharesV1(recData, decryptor, ersLabel)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error recovering key shares: %s", err)
	}

	masterChainCode, err = recoverWrappedData(recData.MasterChainCode, recData.MasterChainCodeKey, decryptor, ersLabel)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error recovering master chain code: %s", err)
	}

	reconstructedPrivateKey, err := reconstruct(keyShares, recData.SharingType, recData.Threshold)
	if err != nil {
		return "", nil, nil, fmt.Errorf("error reconstructing private key: %s", err)
	}

	if !publicKey.Curve().G().Mul(reconstructedPrivateKey).Equals(publicKey) {
		return "", nil, nil, fmt.Errorf("recovery data is corrupt: reconstructed the wrong private key")
	}

	return publicKey.Curve().Impl().Params().Name, reconstructedPrivateKey.Encode(), masterChainCode, nil

}

func parseRecoveryDataV1(encodedRecoveryData []byte) (*recoveryDataV1, error) {
	var recData recoveryDataV1
	err := json.Unmarshal(encodedRecoveryData, &recData)
	if err != nil {
		return nil, err
	}

	// Older versions of the recoveryData did not have the threshold included.
	// Based on the sharing type we set the threshold to the most commonly used value.

	if recData.Threshold == 0 {
		switch recData.SharingType {
		case additive, multiplicative:
			recData.Threshold = len(recData.KeyParts) - 1
		case shamir:
			if len(recData.KeyParts) == 2 {
				recData.Threshold = 1
			} else {
				recData.Threshold = (len(recData.KeyParts) - 1) / 2
			}
		}
	}

	return &recData, nil
}

func recoverKeySharesV1(recoveryData *recoveryDataV1, decryptor Decryptor, label []byte) (map[int]math.Scalar, math.Point, error) {
	publicKey, err := recoverPublicKey(recoveryData.PublicKey)
	if err != nil {
		return nil, math.Point{}, fmt.Errorf("error getting public key from recovery data: %w", err)
	}

	keyParts := make(map[int]recoveryDataKeyPart)
	for i, v := range recoveryData.KeyParts {
		keyParts[i] = v
	}
	keyShares, err := recoverKeyShares(publicKey.Curve(), keyParts, decryptor, label)
	if err != nil {
		return nil, math.Point{}, err
	}

	return keyShares, publicKey, nil

}
