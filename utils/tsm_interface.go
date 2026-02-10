// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"crypto/rsa"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/tsm"
)

//go:generate mockgen -destination=mocks/mock_tsm_client.go -package=mocks github.com/palisadeinc/wallet-recovery-cli/utils TSMClient

// TSMClient is an interface that wraps the TSM SDK functions used for key recovery.
// This interface allows for easier testing by enabling mock implementations.
type TSMClient interface {
	// ECDSAValidateRecoveryData validates ECDSA recovery data
	ECDSAValidateRecoveryData(recoveryData, publicKey []byte, ersPublicKey *rsa.PublicKey, label []byte) error

	// ECDSARecoverPrivateKey recovers an ECDSA private key from recovery data
	ECDSARecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, label []byte) (*tsm.ECDSARecoveredPrivateKey, error)

	// ECDSADerivePrivateKey derives an ECDSA private key from master key and chain code
	ECDSADerivePrivateKey(masterKey, chainCode []byte, path []uint32) ([]byte, error)

	// SchnorrValidateRecoveryData validates Schnorr (ED25519) recovery data
	SchnorrValidateRecoveryData(recoveryData, publicKey []byte, ersPublicKey *rsa.PublicKey, label []byte) error

	// SchnorrRecoverPrivateKey recovers a Schnorr (ED25519) private key from recovery data
	SchnorrRecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, label []byte) (*tsm.SchnorrRecoveredPrivateKey, error)
}

// DefaultTSMClient is the default implementation that wraps the actual TSM SDK functions
type DefaultTSMClient struct{}

// ECDSAValidateRecoveryData validates ECDSA recovery data using the TSM SDK
func (c *DefaultTSMClient) ECDSAValidateRecoveryData(recoveryData, publicKey []byte, ersPublicKey *rsa.PublicKey, label []byte) error {
	return tsm.ECDSAValidateRecoveryData(recoveryData, publicKey, ersPublicKey, label)
}

// ECDSARecoverPrivateKey recovers an ECDSA private key using the TSM SDK
func (c *DefaultTSMClient) ECDSARecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, label []byte) (*tsm.ECDSARecoveredPrivateKey, error) {
	return tsm.ECDSARecoverPrivateKey(recoveryData, ersPrivateKey, label)
}

// ECDSADerivePrivateKey derives an ECDSA private key using the TSM SDK
func (c *DefaultTSMClient) ECDSADerivePrivateKey(masterKey, chainCode []byte, path []uint32) ([]byte, error) {
	return tsm.ECDSADerivePrivateKey(masterKey, chainCode, path)
}

// SchnorrValidateRecoveryData validates Schnorr recovery data using the TSM SDK
func (c *DefaultTSMClient) SchnorrValidateRecoveryData(recoveryData, publicKey []byte, ersPublicKey *rsa.PublicKey, label []byte) error {
	return tsm.SchnorrValidateRecoveryData(recoveryData, publicKey, ersPublicKey, label)
}

// SchnorrRecoverPrivateKey recovers a Schnorr private key using the TSM SDK
func (c *DefaultTSMClient) SchnorrRecoverPrivateKey(recoveryData []byte, ersPrivateKey *rsa.PrivateKey, label []byte) (*tsm.SchnorrRecoveredPrivateKey, error) {
	return tsm.SchnorrRecoverPrivateKey(recoveryData, ersPrivateKey, label)
}
