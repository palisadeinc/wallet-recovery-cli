package ers

import (
	"crypto/rsa"
	"gitlab.com/sepior/go-tsm-sdkv2/ec"
)

func RecoveryDataFinalize(partialRecoveryData []PartialRecoveryData, ersPublicKey *rsa.PublicKey, ersLabel []byte) (RecoveryData, error) {
	return recoveryDataFinalize(partialRecoveryData, ersPublicKey, ersLabel, nil)
}

func RecoveryDataFinalizeWithExternalValidation(partialRecoveryData []PartialRecoveryData, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKey ec.Point) (RecoveryData, error) {
	return recoveryDataFinalize(partialRecoveryData, ersPublicKey, ersLabel, &externalPublicKey)
}

func recoveryDataFinalize(partialRecoveryData []PartialRecoveryData, ersPublicKey *rsa.PublicKey, ersLabel []byte, externalPublicKey *ec.Point) (RecoveryData, error) {
	recoveryData := RecoveryData{
		Version:             Version,
		PartialRecoveryData: partialRecoveryData,
	}

	_, _, _, err := validate(recoveryData, ersPublicKey, ersLabel, externalPublicKey)
	if err != nil {
		return RecoveryData{}, err
	}

	return recoveryData, nil
}
