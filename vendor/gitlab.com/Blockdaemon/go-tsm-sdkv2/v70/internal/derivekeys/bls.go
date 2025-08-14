package derivekeys

import (
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/caching"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
)

func DeriveBLSKeys(publicKey ec.Point, privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedKeys, error) {
	if len(chainPath) > 0 {
		return DerivedKeys{}, fmt.Errorf("key derivation is currently not supported for BLS")
	}

	return DerivedKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ChainCode:  chainCode,
	}, nil
}

func DeriveBLSPublicKey(publicKey ec.Point, chainCode []byte, chainPath []uint32, cache caching.Cache) (DerivedPublicKey, error) {
	if len(chainPath) > 0 {
		return DerivedPublicKey{}, fmt.Errorf("key derivation is currently not supported for BLS")
	}

	return DerivedPublicKey{
		PublicKey: publicKey,
		ChainCode: chainCode,
	}, nil
}
func DeriveBLSPrivateKey(privateKey ec.Scalar, chainCode []byte, chainPath []uint32, cache caching.Cache) (ec.Scalar, error) {
	if len(chainPath) > 0 {
		return ec.Scalar{}, fmt.Errorf("key derivation is currently not supported for BLS")
	}

	return privateKey, nil
}
