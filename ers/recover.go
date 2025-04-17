package ers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
	"github.com/palisadeinc/mpc-recovery/math"
)

func recoverWrappedData(encData, wrappedEncKey []byte, decryptor Decryptor, label []byte) ([]byte, error) {
	encKey, err := decryptor.Decrypt(wrappedEncKey, label)
	if err != nil {
		return nil, fmt.Errorf("unable to unwrap encryption key: %w", err)
	}

	c, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-GCM cipher: %w", err)
	}
	zeroNonce := make([]byte, gcm.NonceSize())
	data, err := gcm.Open(nil, zeroNonce, encData, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt data: %w", err)
	}

	return data, nil
}

func recoverKeyShares(curve math.Curve, keyParts map[int]recoveryDataKeyPart, decryptor Decryptor, label []byte) (map[int]math.Scalar, error) {
	keyShares := make(map[int]math.Scalar)
	for keyPartIndex, keyPart := range keyParts {
		// Leave index 0 as a placeholder for the decrypted value. The other entries are set to the plaintext values
		indices := make([]math.Scalar, 1, len(keyPart.Values)+1)
		vals := make([]math.Scalar, 1, len(keyPart.Values)+1)
		for j, value := range keyPart.Values {
			indices = append(indices, curve.NewScalarInt(j))
			v := curve.NewScalarBytes(value)
			vals = append(vals, v)
		}

		keyShareCommitment, err := curve.DecodePoint(keyPart.PartCommitment)
		if err != nil {
			return nil, err
		}

		keyShareRecovered := false
		for j, encryptedValue := range keyPart.EncryptedValues {
			value, err := decryptor.Decrypt(encryptedValue, label)
			if err != nil {
				// Decryption failed. Skip this entry and try the next encrypted value
				continue
			}

			// Update the list of plaintext values with the decrypted value
			indices[0] = curve.NewScalarInt(j)
			vals[0] = curve.NewScalarBytes(value)

			// Now we have k+1 plaintext values, so we try to reconstruct the secret key share
			keyShare, err := math.LagrangeReconstruct(curve.NewScalarInt(0), k, indices, vals)
			if err != nil {
				// If reconstruction fails skip this value and try the next one
				continue
			}

			// Verify the recovered value using the Feldman commitment
			if curve.G().Mul(keyShare).Equals(keyShareCommitment) {
				// If the recovered value matches the commitment then we are done
				keyShares[keyPartIndex] = keyShare
				keyShareRecovered = true
				break
			}
		}
		if !keyShareRecovered {
			return nil, fmt.Errorf("unable to recover key share %d", keyPartIndex)
		}
	}

	return keyShares, nil
}

func recoverPublicKey(publicKeyBytes []byte) (math.Point, error) {
	publicKey, err := ParsePublicKey(publicKeyBytes)
	if err != nil {
		return math.Point{}, err
	}

	switch publicKey := publicKey.(type) {
	case *ecdsa.PublicKey:
		curve, err := math.NewCurve(publicKey.Curve.Params().Name)
		if err != nil {
			return math.Point{}, err
		}
		return curve.NewPoint(publicKey.X, publicKey.Y)
	case ed25519.PublicKey:
		curve, err := math.NewCurve("ED-25519")
		if err != nil {
			return math.Point{}, err
		}
		return curve.DecodePoint(publicKey)
	default:
		return math.Point{}, fmt.Errorf("unsupported public key type in recovery data")
	}
}
