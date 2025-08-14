package transport

type AN10922WrappingKeyResponse struct {
	WrappingKey []byte `json:"wrappingKey"`
}

type AN10922SymImport128Request struct {
	KeyShare []byte `json:"keyShare"`
}

type AN10922SymImport128Response struct {
	KeyID string `json:"keyID"`
}

type AN10922DeriveRequest struct {
	Data []byte `json:"data"`
}

type AN10922DeriveResponse struct {
	KeyID string `json:"keyID"`
}

type AN10922ChecksumResponse struct {
	Checksum        []byte `json:"checksum"`
	PartialChecksum []byte `json:"partialChecksum"`
}
