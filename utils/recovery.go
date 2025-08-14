package utils

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/pkg/errors"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/tsm"
)

// convertPKIXToJSON converts a PKIX public key to the JSON format expected by TSM SDK v70
func convertPKIXToJSON(pkixBytes []byte, keyType string) ([]byte, error) {
	// For now, we'll extract the raw key directly from the PKIX bytes
	// since we know the exact format for our keys
	
	var jsonKey map[string]string
	
	switch keyType {
	case "SECP256K1", "ECDSA":
		// For SECP256K1, extract the raw public key bytes (uncompressed)
		// The PKIX format contains the raw public key after the header
		// For secp256k1, we expect 65 bytes (0x04 + 32 bytes X + 32 bytes Y)
		if len(pkixBytes) < 65 {
			return nil, fmt.Errorf("invalid SECP256K1 public key length")
		}
		// Find the raw key (last 65 bytes for uncompressed secp256k1)
		rawKey := pkixBytes[len(pkixBytes)-65:]
		if rawKey[0] != 0x04 {
			// Try compressed format (33 bytes)
			rawKey = pkixBytes[len(pkixBytes)-33:]
		}
		
		jsonKey = map[string]string{
			"scheme": "ECDSA",
			"curve":  "secp256k1",
			"point":  base64.StdEncoding.EncodeToString(rawKey),
		}
		
	case "ED25519":
		// For ED25519, the PKIX format contains a 32-byte public key
		// The DER encoding is: 302a300506032b6570032100 + 32 bytes
		if len(pkixBytes) != 44 {
			return nil, fmt.Errorf("invalid ED25519 public key length: expected 44, got %d", len(pkixBytes))
		}
		// Extract the 32-byte raw public key (starts at offset 12)
		rawKey := pkixBytes[12:]
		
		jsonKey = map[string]string{
			"scheme": "Ed25519",
			"curve":  "ED-25519",
			"point":  base64.StdEncoding.EncodeToString(rawKey),
		}
		
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
	
	jsonBytes, err := json.Marshal(jsonKey)
	if err != nil {
		return nil, errors.WithMessage(err, "failed to marshal JSON public key")
	}
	
	return jsonBytes, nil
}

// RecoverECDSAPrivateKey recovers ECDSA private key (for SECP256K1/Ethereum)
func RecoverECDSAPrivateKey(
	recoveryDataBytes, rootWalletKeyPkix []byte, quorumID, keyID uuid.UUID, ersRSAPrivateKey *rsa.PrivateKey,
	ersPublicKey *rsa.PublicKey,
) ([]byte, error) {
	ersLabel := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", quorumID, keyID)))
	
	// Convert PKIX public key to JSON format for TSM SDK v70
	jsonPublicKey, err := convertPKIXToJSON(rootWalletKeyPkix, "SECP256K1")
	if err != nil {
		return nil, errors.WithMessage(err, "error converting public key to JSON format")
	}
	
	if err := tsm.ECDSAValidateRecoveryData(
		recoveryDataBytes, jsonPublicKey, ersPublicKey, ersLabel[:],
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
	ersLabel := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", quorumID, keyID)))
	
	// Convert PKIX public key to JSON format for TSM SDK v70
	jsonPublicKey, err := convertPKIXToJSON(rootWalletKeyPkix, "ED25519")
	if err != nil {
		return nil, errors.WithMessage(err, "error converting public key to JSON format")
	}
	
	if err := tsm.SchnorrValidateRecoveryData(
		recoveryDataBytes, jsonPublicKey, ersPublicKey, ersLabel[:],
	); err != nil {
		return nil, errors.WithMessage(err, "error validating ED25519 recovery data")
	}

	masterPrivateKey, err := tsm.SchnorrRecoverPrivateKey(recoveryDataBytes, ersRSAPrivateKey, ersLabel[:])
	if err != nil {
		return nil, errors.WithMessage(err, "error recovering ED25519 private key")
	}

	// Make a copy of the private key before clearing the original
	privateKeyCopy := make([]byte, len(masterPrivateKey.PrivateKey))
	copy(privateKeyCopy, masterPrivateKey.PrivateKey)
	
	defer ClearSensitiveBytes(masterPrivateKey.PrivateKey)
	defer ClearSensitiveBytes(masterPrivateKey.MasterChainCode)

	// TSM returns ED25519 keys as raw scalars in big-endian format, not RFC-8032 seeds
	// The crypto functions will handle the proper conversion for use with standard libraries
	return privateKeyCopy, nil
}
