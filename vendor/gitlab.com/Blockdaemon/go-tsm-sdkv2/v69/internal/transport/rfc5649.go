package transport

type RFC5649BlobImportRequest struct {
	KeyShare []byte `json:"keyShare"`
}

type RFC5649BlobImportResponse struct {
	KeyID string `json:"keyID"`
}

type RFC5649EncryptBlobRequest struct {
	WrappedAesKey []byte `json:"aesKey"`
}

type RFC5649EncryptBlobResponse struct {
	RFC5649PartialResultBytes []byte
}
