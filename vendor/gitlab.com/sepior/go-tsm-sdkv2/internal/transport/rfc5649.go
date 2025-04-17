package transport

type RFC5649BlobImportRequest struct {
	KeyShare   []byte `json:"keyShare"`
	SessionKey []byte `json:"sessionKey"`
}

type RFC5649BlobImportResponse struct {
	KeyID string `json:"keyID"`
}

type RFC5649EncryptBlobRequest struct {
	WrappedAesKey []byte `json:"aesKey"`
}

type RFC5649EncryptBlobResponse struct {
	Encryption []byte `json:"encryption"`
}
