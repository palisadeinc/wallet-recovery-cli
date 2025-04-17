package ers

import (
	"crypto/rsa"
	"fmt"
)

func ValidateRecoveryData(ersPublicKey rsa.PublicKey, label []byte, publicKeyBytes, recoveryData []byte) error {

	if publicKeyBytes == nil {
		return fmt.Errorf("validation requires public key")
	}

	version, err := getVersion(recoveryData)
	if err != nil {
		return err
	}

	switch version {
	case RecoveryDataVersion1:
		return fmt.Errorf("validation requires recovery data version 2 or later")
	case RecoveryDataVersion2:
		return validateJSONV2(ersPublicKey, label, publicKeyBytes, recoveryData)
	case RecoveryDataVersion3:
		return validateJSONV3(ersPublicKey, label, publicKeyBytes, recoveryData)
	default:
		return fmt.Errorf("validation not supported for recovery data version: %s", version)
	}

}
