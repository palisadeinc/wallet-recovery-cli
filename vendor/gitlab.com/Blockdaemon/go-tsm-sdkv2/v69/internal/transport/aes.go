package transport

type AESKeyGenRequest struct {
	Threshold    int
	KeyLength    int
	DesiredKeyID string
}

type AESKeyGenResponse struct {
	KeyID string
}

type AESKeyImportRequest struct {
	Threshold    int
	KeyShare     []byte
	Checksum     []byte
	DesiredKeyID string
}

type AESKeyImportResponse struct {
	KeyID string
}

type AESKeyExportRequest struct {
	WrappingKey []byte
}

type AESKeyExportResponse struct {
	WrappedKeyShare []byte
	Checksum        []byte
}

type AESCTRRequest struct {
	KeyStreamLength int
	IV              []byte
}

type AESCTRResponse struct {
	PartialAESCTRResult []byte
}

type AESCBCEncryptRequest struct {
	IV        []byte
	Plaintext []byte
}

type AESCBCEncryptResponse struct {
	PartialAESCBCEncryptResult []byte
}

type AESCBCDecryptRequest struct {
	IV         []byte
	Ciphertext []byte
}

type AESCBCDecryptResponse struct {
	PartialAESCBCDecryptResult []byte
}

type AESGCMEncryptRequest struct {
	IV             []byte
	Plaintext      []byte
	AdditionalData []byte
}

type AESGCMEncryptResponse struct {
	PartialAESGCMEncryptResult []byte
}

type AESGCMDecryptRequest struct {
	IV             []byte
	Ciphertext     []byte
	AdditionalData []byte
	Tag            []byte
}

type AESGCMDecryptResponse struct {
	PartialAESGCMDecryptResult []byte
}

type AESCMACRequest struct {
	Data []byte
}

type AESCMACResponse struct {
	PartialAESCMACResult []byte
}
