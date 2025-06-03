package transport

import (
	"crypto"
)

type RSAKeyExportRequest struct {
	WrappingKey []byte `json:"wrappingKey"`
}

type RSAKeyExportResponse struct {
	WrappedKeyShare []byte `json:"wrappedKeyShare"`
	PublicKey       []byte `json:"publicKey"`
}

type RSAKeyImportRequest struct {
	KeyID           string `json:"keyID"`
	WrappedKeyShare []byte `json:"wrappedKeyShare"`
}

type RSAKeyImportResponse struct {
	KeyID string `json:"keyID"`
}

type RSAPublicKeyResponse struct {
	PublicKey []byte `json:"publicKey"`
}

type RSASignRequest struct {
	Hash        crypto.Hash `json:"hash"`
	MessageHash []byte      `json:"messageHash"`
	Players     []int       `json:"players"`
}

type RSASignResponse struct {
	PartialSignature []byte `json:"partialSignature"`
}

type RSADecryptRequest struct {
	Ciphertext []byte `json:"ciphertext"`
	Players    []int  `json:"players"`
}

type RSADecryptResponse struct {
	PartialDecryption []byte `json:"partialDecryption"`
}
