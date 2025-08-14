package transport

type PKCS11KeyGenAESRequest struct {
	Threshold       int
	KeyLength       int
	DesiredObjectID string

	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11KeyGenAESResponse struct {
	ObjectID string
}

type PKCS11ImportAESRequest struct {
	Threshold       int
	KeyShare        []byte
	Checksum        []byte
	DesiredObjectID string

	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11ImportAESResponse struct {
	ObjectID string
}

type PKCS11ExportAESRequest struct {
	WrappingKey []byte
}

type PKCS11ExportAESResponse struct {
	WrappedKeyShare []byte
	Checksum        []byte

	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11EncryptAESGCMRequest struct {
	IV             []byte
	Plaintext      []byte
	AdditionalData []byte
}

type PKCS11EncryptAESGCMResponse struct {
	PartialAESGCMEncryptResult []byte
}

type PKCS11DecryptAESGCMRequest struct {
	IV             []byte
	Ciphertext     []byte
	AdditionalData []byte
	Tag            []byte
}

type PKCS11DecryptAESGCMResponse struct {
	PartialAESGCMDecryptResult []byte
}

type PKCS11EncryptAESCBCRequest struct {
	IV        []byte
	Plaintext []byte
}

type PKCS11EncryptAESCBCResponse struct {
	PartialAESCBCEncryptResult []byte
}

type PKCS11DecryptAESCBCRequest struct {
	IV         []byte
	Ciphertext []byte
}

type PKCS11DecryptAESCBCResponse struct {
	PartialAESCBCDecryptResult []byte
}

type PKCS11GetObjectResponse struct {
	ObjectID    string
	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11DeleteObjectResponse struct {
	ObjectID string
}

type PKCS11InsertObjectRequest struct {
	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11InsertObjectResponse struct {
	ObjectID string
}

type PKCS11UpdateObjectRequest struct {
	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11UpdateObjectResponse struct {
	ObjectID string
}

type PKCS11FindObjectRequest struct {
	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}

type PKCS11FindObjectResponse struct {
	Objects []PKCS11Object
}

type PKCS11Object struct {
	ObjectID    string
	Label       string
	ObjectClass uint32
	KeyType     uint32
	Blob        []byte
}
