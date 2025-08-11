package ers

import (
	"crypto/rsa"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
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
