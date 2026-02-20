package blsvariant

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
)

// Names for BLS variants. DO NOT change these values!
const (
	BLS12381MinimalSignatureSize = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
	BLS12381MinimalPubKeySize    = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
)

func VariantToSignatureCurve(blsVariant string) (ec.Curve, error) {
	switch blsVariant {
	case BLS12381MinimalSignatureSize:
		return ec.BLS12381E1, nil
	case BLS12381MinimalPubKeySize:
		return ec.BLS12381E2, nil
	}
	return nil, fmt.Errorf("no elliptic curve for BLS variant: %s", blsVariant)
}

func VariantToPublicKeyCurve(blsVariant string) (ec.Curve, error) {
	switch blsVariant {
	case BLS12381MinimalSignatureSize:
		return ec.BLS12381E2, nil
	case BLS12381MinimalPubKeySize:
		return ec.BLS12381E1, nil
	}
	return nil, fmt.Errorf("no elliptic curve for BLS variant: %s", blsVariant)
}
