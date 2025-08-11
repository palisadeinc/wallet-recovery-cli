package transport

type HMACKeyGenRequest struct {
	Threshold    int
	KeyLength    int
	DesiredKeyID string
}

type HMACKeyGenResponse struct {
	KeyID string
}

type HMACKeyImportRequest struct {
	DesiredKeyID string
	Threshold    int
	KeyShare     []byte
	Checksum     []byte
}

type HMACKeyImportResponse struct {
	KeyID string
}

type HMACKeyExportRequest struct {
	WrappingKey []byte
}

type HMACKeyExportResponse struct {
	WrappedKeyShare []byte
	Checksum        []byte
}

type HMACSHA2Request struct {
	Data []byte
}

type HMACSHA2Response struct {
	HMACPartialResult []byte
}
