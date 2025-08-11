package schnorrvariant

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
)

// Names for schnorr variants. DO NOT change these values!
const (
	Ed25519        = "Ed25519"
	Ed448          = "Ed448"
	BIP340         = "BIP-340"
	MinaSchnorr    = "MinaSchnorr"
	ZilliqaSchnorr = "ZilliqaSchnorr"
	Sr25519        = "Sr25519"
)

func VariantToCurve(schnorrVariant string) (ec.Curve, error) {
	switch schnorrVariant {
	case Ed25519:
		return ec.Edwards25519, nil
	case Ed448:
		return ec.Edwards448, nil
	case BIP340, ZilliqaSchnorr:
		return ec.Secp256k1, nil
	case MinaSchnorr:
		return ec.PallasMina, nil
	case Sr25519:
		return ec.Ristretto255, nil
	}
	return nil, fmt.Errorf("no elliptic curve for schnorr variant: %s", schnorrVariant)
}
