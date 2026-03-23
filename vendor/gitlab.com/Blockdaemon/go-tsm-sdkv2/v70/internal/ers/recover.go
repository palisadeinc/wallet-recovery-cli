package ers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ec"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/polynomial"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/secretshare"
)

type Decryptor interface {
	Decrypt(ciphertext, label []byte) (plaintext []byte, err error)
	PublicKey() (*rsa.PublicKey, error)
}

type DefaultDecryptor struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewDefaultDecryptor(privateKey *rsa.PrivateKey) *DefaultDecryptor {
	return &DefaultDecryptor{
		privateKey: privateKey,
		publicKey:  privateKey.Public().(*rsa.PublicKey),
	}
}

func (d *DefaultDecryptor) Decrypt(ciphertext, label []byte) (plaintext []byte, err error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, d.privateKey, ciphertext, label)

}

func (d *DefaultDecryptor) PublicKey() (*rsa.PublicKey, error) {
	return d.publicKey, nil
}

func RecoverPrivateKey(recoveryData RecoveryData, ersDecryptor Decryptor, ersLabel []byte) (ec.Scalar, error) {
	ersPublicKey, err := ersDecryptor.PublicKey()
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("failed to fetch ERS public key: %w", err)
	}

	threshold, sharingType, keyParts, err := validate(recoveryData, ersPublicKey, ersLabel, nil)
	if err != nil {
		return ec.Scalar{}, fmt.Errorf("invalid recovery data: %w", err)
	}

	curve, err := ec.NewCurve(recoveryData.PartialRecoveryData[0].Curve)
	if err != nil {
		return ec.Scalar{}, err
	}

	keyShares := make(map[int]ec.Scalar, len(keyParts))
	for keyPartIndex, keyPart := range keyParts {
		// Leave index 0 as a placeholder for the decrypted value. The other entries are set to the plaintext values
		indices := make([]ec.Scalar, 1, len(keyPart.Values)+1)
		vals := make([]ec.Scalar, 1, len(keyPart.Values)+1)

		for j, value := range keyPart.Values {
			indices = append(indices, curve.Zn().NewScalarIntWithModularReduction(j))
			v, err := curve.Zn().DecodeScalar(value)
			if err != nil {
				return ec.Scalar{}, err
			}
			vals = append(vals, v)
		}

		keyShareCommitment, err := curve.DecodePoint(keyPart.PartCommitment, true)
		if err != nil {
			return ec.Scalar{}, err
		}

		for j, encryptedValue := range keyPart.EncryptedValues {
			value, err := ersDecryptor.Decrypt(encryptedValue, ersLabel)
			if err != nil {
				// Decryption failed. Skip this entry and try the next encrypted value
				continue
			}
			indices[0] = curve.Zn().NewScalarIntWithModularReduction(j)
			vals[0], err = curve.Zn().DecodeScalar(value)
			if err != nil {
				// Failed to decode the decrypted value. Skip this entry and try the next encrypted value
				continue
			}

			keyShare := polynomial.Interpolate(curve.Zn().Zero(), K, indices, vals)
			if curve.G().Multiply(keyShare).Equals(keyShareCommitment) {
				// If the recovered value matches the commitment then we are done
				keyShares[keyPartIndex] = keyShare
				break
			}
		}
	}

	return reconstruct(threshold, sharingType, curve.Zn(), keyShares)
}

func RecoverAuxDataPublic(recoveryData RecoveryData) []byte {
	return recoveryData.PartialRecoveryData[0].AuxDataPublic
}

func RecoverAuxDataPrivate(recoveryData RecoveryData, ersDecryptor Decryptor, ersLabel []byte) ([]byte, error) {
	encryptedAuxDataEncryptionKey := recoveryData.PartialRecoveryData[0].AuxDataWrappedEncryptionKey
	encryptedPrivateAuxData := recoveryData.PartialRecoveryData[0].AuxDataPrivateEncrypted

	auxDataEncryptionKey, err := ersDecryptor.Decrypt(encryptedAuxDataEncryptionKey, ersLabel)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt aux data encryption key: %w", err)
	}

	c, err := aes.NewCipher(auxDataEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-GCM cipher: %w", err)
	}
	zeroNonce := make([]byte, gcm.NonceSize())
	privateAuxData, err := gcm.Open(nil, zeroNonce, encryptedPrivateAuxData, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt aux data: %w", err)
	}

	return privateAuxData, nil
}

func reconstruct(threshold int, sharingType string, field ec.Field, shares map[int]ec.Scalar) (ec.Scalar, error) {
	if len(shares) < 2 {
		return ec.Scalar{}, fmt.Errorf("not enough shares to reconstruct: %d", len(shares))
	}
	if threshold < 1 || threshold >= len(shares) {
		return ec.Scalar{}, fmt.Errorf("not enough shares to reconstruct for threshold: %d", threshold)
	}

	switch sharingType {
	case secretshare.ShamirSharing.String():
		return shamirReconstruct(field, threshold, shares), nil
	case secretshare.AdditiveSharing.String():
		return additiveReconstruct(field, shares), nil
	}
	return ec.Scalar{}, fmt.Errorf("unsupported sharing type: %s", sharingType)
}

func additiveReconstruct(field ec.Field, shares map[int]ec.Scalar) ec.Scalar {
	result := field.Zero()
	for _, share := range shares {
		result = result.Add(share)
	}
	return result
}

func shamirReconstruct(field ec.Field, threshold int, shares map[int]ec.Scalar) ec.Scalar {
	return polynomial.InterpolatePlayers(field.Zero(), threshold, shares)
}
