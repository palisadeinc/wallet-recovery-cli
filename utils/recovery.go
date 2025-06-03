package utils

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/tsm"
)

func RecoverPrivateKey(recoveryDataBytes, rootWalletKeyPkix []byte, quorumID, keyID uuid.UUID, ersRSAPrivateKey *rsa.PrivateKey, ersPublicKey *rsa.PublicKey) ([]byte, error) {
	ersLabel := sha256.Sum256(fmt.Appendf(nil, "%s-%s", quorumID, keyID))
	if err := tsm.ECDSAValidateRecoveryData(recoveryDataBytes, rootWalletKeyPkix, ersPublicKey, ersLabel[:]); err != nil {
		return nil, errors.WithMessage(err, "error validating recovery data")
	}

	masterPrivateKey, err := tsm.ECDSARecoverPrivateKey(recoveryDataBytes, ersRSAPrivateKey, ersLabel[:])
	if err != nil {
		return nil, errors.WithMessage(err, "error recovering private key")
	}

	defer ClearSensitiveBytes(masterPrivateKey.PrivateKey)
	defer ClearSensitiveBytes(masterPrivateKey.MasterChainCode)

	privateKeyBytes, err := tsm.ECDSADerivePrivateKey(masterPrivateKey.PrivateKey, masterPrivateKey.MasterChainCode, []uint32{0})
	if err != nil {
		return nil, errors.WithMessage(err, "error deriving private key")
	}

	return privateKeyBytes, nil
}
