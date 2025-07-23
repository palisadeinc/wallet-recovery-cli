package utils

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/tsm"
)

// RecoverECDSAPrivateKey recovers ECDSA private key (for SECP256K1/Ethereum)
func RecoverECDSAPrivateKey(
	recoveryDataBytes, rootWalletKeyPkix []byte, quorumID, keyID uuid.UUID, ersRSAPrivateKey *rsa.PrivateKey,
	ersPublicKey *rsa.PublicKey,
) ([]byte, error) {
	ersLabel := sha256.Sum256(fmt.Appendf(nil, "%s-%s", quorumID, keyID))
	if err := tsm.ECDSAValidateRecoveryData(
		recoveryDataBytes, rootWalletKeyPkix, ersPublicKey, ersLabel[:],
	); err != nil {
		return nil, errors.WithMessage(err, "error validating recovery data")
	}

	masterPrivateKey, err := tsm.ECDSARecoverPrivateKey(recoveryDataBytes, ersRSAPrivateKey, ersLabel[:])
	if err != nil {
		return nil, errors.WithMessage(err, "error recovering private key")
	}

	defer ClearSensitiveBytes(masterPrivateKey.PrivateKey)
	defer ClearSensitiveBytes(masterPrivateKey.MasterChainCode)

	privateKeyBytes, err := tsm.ECDSADerivePrivateKey(
		masterPrivateKey.PrivateKey, masterPrivateKey.MasterChainCode, []uint32{0},
	)
	if err != nil {
		return nil, errors.WithMessage(err, "error deriving private key")
	}

	return privateKeyBytes, nil
}

// RecoverED25519PrivateKey recovers ED25519 private key (for Solana)
func RecoverED25519PrivateKey(
	recoveryDataBytes, rootWalletKeyPkix []byte, quorumID, keyID uuid.UUID, ersRSAPrivateKey *rsa.PrivateKey,
	ersPublicKey *rsa.PublicKey,
) ([]byte, error) {
	ersLabel := sha256.Sum256(fmt.Appendf(nil, "%s-%s", quorumID, keyID))
	if err := tsm.SchnorrValidateRecoveryData(
		recoveryDataBytes, rootWalletKeyPkix, ersPublicKey, ersLabel[:],
	); err != nil {
		return nil, errors.WithMessage(err, "error validating ED25519 recovery data")
	}

	masterPrivateKey, err := tsm.SchnorrRecoverPrivateKey(recoveryDataBytes, ersRSAPrivateKey, ersLabel[:])
	if err != nil {
		return nil, errors.WithMessage(err, "error recovering ED25519 private key")
	}

	defer ClearSensitiveBytes(masterPrivateKey.PrivateKey)
	defer ClearSensitiveBytes(masterPrivateKey.MasterChainCode)

	// For ED25519, we use multiplicative derivation
	privateKeyBytes, err := tsm.SchnorrDerivePrivateKey(
		tsm.SchnorrAlgorithmEd25519, masterPrivateKey.PrivateKey, masterPrivateKey.MasterChainCode, []uint32{0},
	)
	if err != nil {
		return nil, errors.WithMessage(err, "error deriving ED25519 private key")
	}

	return privateKeyBytes, nil
}
