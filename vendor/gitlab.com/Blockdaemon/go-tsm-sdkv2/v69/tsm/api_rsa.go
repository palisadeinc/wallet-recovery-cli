package tsm

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/transport"
	"net/http"
)

const (
	HashFunctionNone   string = ""
	HashFunctionSHA1   string = "SHA1"
	HashFunctionSHA256 string = "SHA256"
)

func getHashFunction(hashFunction string) (crypto.Hash, error) {
	switch hashFunction {
	case HashFunctionNone:
		return crypto.Hash(0), nil
	case HashFunctionSHA1:
		return crypto.SHA1, nil
	case HashFunctionSHA256:
		return crypto.SHA256, nil
	default:
		return 0, fmt.Errorf("unsupported hash function '%s'", hashFunction)
	}
}

// RSAWrappedKeyShare contains an envelope wrapped (encrypted) key share as well as the corresponding public key.
type RSAWrappedKeyShare struct {
	WrappedKeyShare []byte
	PKIXPublicKey   []byte
}

type RSAAPI interface {
	// ImportKeyShares instructs the player to participate in an MPC session that imports key shares of an RSA key.
	//
	// The import session only succeeds if all players in the session agree on the public key, which is part of each
	// key share, and the imported key matches this public key.
	//
	// Keys shares must be encrypted under the wrapping key of the player who receives a given key share. Wrapping keys
	// can be obtained by calling WrappingKey() on each of the players. You can either use these wrapping keys to export
	// wrapped key shares from an existing TSM, or you can use them to wrap key shares of an existing RSA key.
	//
	// To import an existing RSA key, use the helper function tsmutils.RSASecretShare to split the key into shares, and
	// tsmutils.EnvelopeWrap() to wrap each share with the wrapping keys obtained from calls to WrappingKey() on each of
	// the players.
	//
	// Output:
	//   - keyID: The ID of the imported key.
	ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, wrappedKeyShare []byte, desiredKeyID string) (keyID string, err error)

	// ExportKeyShares instructs the player to participate in an MPC session that exports key shares of an existing RSA key.
	//
	// The exported private key share will be encrypted under the provided wrapping key. A wrapped RSA key
	// share can be unwrapped with the tsmutils.EnvelopeUnwrap method. If at least threshold + 1 key shares are
	// present, the RSA private key can be recovered using the tsmutils.RSARecombine method.
	//
	// Each player is configured with a whitelist of wrapping keys and only accepts to export if the provided wrapping
	// key matches the whitelist.
	//
	// Input:
	//   - keyID: The ID of an existing RSA key in the TSM.
	//   - wrappingKey: The wrapping key used to encrypt the key share before exporting it. Must be provided as an
	//     ASN.1 DER encoding of a SubjectPublicKeyInfo (see RFC 5280, Section 4.1). The wrapping key of a target TSM
	//     can be obtained by WrappingKey().
	//
	// Output:
	//   - wrappedKeyShare: The wrapped key share exported to this player. The key share also contains the public key
	//     corresponding to the exported private key shares.
	ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *RSAWrappedKeyShare, err error)

	// PublicKey returns the public key corresponding to a given RSA key in the TSM.
	//
	// CAVEAT: Only use the returned public key, e.g., for creating an address on a blockchain, if you trust this player.
	// External parties should generally only trust a public key from the TSM if it was obtained from at least
	// threshold + 1 different players, and all the obtained public keys are identical.
	//
	// Input:
	//   - keyID: The ID of an RSA key in the TSM.
	//
	// Output:
	//   - pkixPublicKey: A public RSA key as an ASN.1 DER encoding of SubjectPublicKeyInfo.
	PublicKey(ctx context.Context, keyID string) (pkixPublicKey []byte, err error)

	// SignPKCS1v15 calculates the signature of hashed using RSASSA-PKCS1-V1_5-SIGN from RSA PKCS #1 v1.5.  Note that
	// hashed must be the result of hashing the input message using the given hash function. If hash is HashFunctionNone,
	// hashed is signed directly. This isn't advisable except for interoperability.
	//
	// Input:
	//   - keyID: The ID of an RSA key in the TSM.
	//   - hashFunction: Hash function used to produce hashed.
	//   - hashed: Hash of the message to be signed.
	//
	// Output:
	//   - signResult: The partial signature for this player. Use RSAFinalizeSignaturePKCS1v15 to combine partial signatures
	//	   into a full signature.
	SignPKCS1v15(ctx context.Context, keyID string, hashFunction string, hashed []byte) (signResult []byte, err error)

	// SignPSS instructs the player to participate in an MPC session that calculates the signature of digest using PSS.
	//
	// Note that digest must be the result of hashing the input message using the given hash function. The salt size
	// used in PSS is the same length as the output length of the hash function.
	//
	// Input:
	//   - keyID: The ID of an RSA key in the TSM.
	//   - hashFunction: Hash function used to produce digest.
	//   - digest: Hash of the message to be signed.
	//
	// Output:
	//   - signResult: The partial signature for this player. Use RSAFinalizeSignaturePSS to combine partial signatures
	//	   into a full signature.
	SignPSS(ctx context.Context, sessionConfig *SessionConfig, keyID string, hashFunction string, digest []byte) (signResult []byte, err error)

	// Decrypt decrypts ciphertext with the RSA private key.
	//
	// Input:
	//   - keyID: The ID of an RSA key in the TSM.
	//   - ciphertext: The ciphertext you want to decrypt.
	//
	// Output:
	//   - decryptionResult: The partial decryption result for this player. Use RSAFinalizeDecryptionPKCS1v15,
	//     RSAFinalizeDecryptionOAEP or RSAFinalizeDecryptionRaw to combine the partial results to the final result
	//     depending on which type of ciphertext you provided to Decrypt.
	Decrypt(ctx context.Context, keyID string, ciphertext []byte) (decryptionResult []byte, err error)
}

type rsaService struct {
	*node
}

func (r *rsaService) ImportKeyShares(ctx context.Context, sessionConfig *SessionConfig, wrappedKeyShare []byte, desiredKeyID string) (keyID string, err error) {
	if desiredKeyID != "" {
		if err = validateKeyID(desiredKeyID); err != nil {
			return "", toTSMError(err, ErrInvalidInput)
		}
	}

	res, err := r.call(ctx, http.MethodPost, "/rsa/keys/import", sessionConfig, r.sendAuthenticatedRequest,
		func() interface{} {
			return transport.RSAKeyImportRequest{
				KeyID:           desiredKeyID,
				WrappedKeyShare: wrappedKeyShare,
			}
		})
	if err != nil {
		return "", toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSAKeyImportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return "", err
	}

	return jsonResponse.KeyID, nil
}

func (r *rsaService) ExportKeyShares(ctx context.Context, sessionConfig *SessionConfig, keyID string, wrappingKey []byte) (wrappedKeyShare *RSAWrappedKeyShare, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := r.call(ctx, http.MethodPost, fmt.Sprintf("/rsa/keys/%s/export", keyID), sessionConfig, r.sendAuthenticatedRequest,
		func() interface{} {
			return transport.RSAKeyExportRequest{
				WrappingKey: wrappingKey,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSAKeyExportResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(jsonResponse.PublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("export key shares: unable to decode public key: %w", err), ErrOperationFailed)
	}
	if _, isRSAPublicKey := publicKey.(*rsa.PublicKey); !isRSAPublicKey {
		return nil, toTSMError(fmt.Errorf("export key shares: public key is not an RSA key: %w", err), ErrOperationFailed)
	}

	return &RSAWrappedKeyShare{
		WrappedKeyShare: jsonResponse.WrappedKeyShare,
		PKIXPublicKey:   jsonResponse.PublicKey,
	}, nil
}

func (r *rsaService) PublicKey(ctx context.Context, keyID string) (pkixPublicKey []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := r.call(ctx, http.MethodGet, fmt.Sprintf("/rsa/keys/%s/publickey", keyID), &SessionConfig{}, r.sendAuthenticatedRequest, nil)
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSAPublicKeyResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(jsonResponse.PublicKey)
	if err != nil {
		return nil, toTSMError(fmt.Errorf("public key: unable to decode public key: %w", err), ErrOperationFailed)
	}
	if _, isRSAPublicKey := publicKey.(*rsa.PublicKey); !isRSAPublicKey {
		return nil, toTSMError(fmt.Errorf("public key: public key is not an RSA key: %w", err), ErrOperationFailed)
	}

	return jsonResponse.PublicKey, nil
}

func (r *rsaService) SignPKCS1v15(ctx context.Context, keyID string, hashFunction string, hashed []byte) (signResult []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	h, err := getHashFunction(hashFunction)
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := r.call(ctx, http.MethodPost, fmt.Sprintf("/rsa/keys/%s/signpkcs1v15", keyID), &SessionConfig{}, r.sendAuthenticatedRequest,
		func() interface{} {
			return transport.RSASignRequest{
				Hash:        h,
				MessageHash: hashed,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSASignResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return jsonResponse.PartialSignature, nil
}

func (r *rsaService) SignPSS(ctx context.Context, sessionConfig *SessionConfig, keyID string, hashFunction string, digest []byte) (signResult []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	h, err := getHashFunction(hashFunction)
	if err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := r.call(ctx, http.MethodPost, fmt.Sprintf("/rsa/keys/%s/signpss", keyID), sessionConfig, r.sendAuthenticatedRequest,
		func() interface{} {
			return transport.RSASignRequest{
				Hash:        h,
				MessageHash: digest,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSASignResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return jsonResponse.PartialSignature, nil
}

func (r *rsaService) Decrypt(ctx context.Context, keyID string, ciphertext []byte) (decryptionResult []byte, err error) {
	if err = validateKeyID(keyID); err != nil {
		return nil, toTSMError(err, ErrInvalidInput)
	}

	res, err := r.call(ctx, http.MethodPost, fmt.Sprintf("/rsa/keys/%s/decrypt", keyID), &SessionConfig{}, r.sendAuthenticatedRequest,
		func() interface{} {
			return transport.RSADecryptRequest{
				Ciphertext: ciphertext,
			}
		})
	if err != nil {
		return nil, toTSMError(err, ErrOperationFailed)
	}

	var jsonResponse transport.RSADecryptResponse
	err = unmarshalJSON(res, &jsonResponse)
	if err != nil {
		return nil, err
	}

	return jsonResponse.PartialDecryption, nil
}
