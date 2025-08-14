package transport

type ECDHKeyGenRequest struct {
	Curve     string `json:"curve"`
	Threshold int    `json:"threshold"`
}

type ECDHKeyGenResponse struct {
	KeyID string `json:"keyID"`
}

type ECDHPublicKeyResponse struct {
	Curve     string `json:"curve"`
	PublicKey []byte `json:"publicKey"`
}

type ECDHComputeSecretRequest struct {
	Curve         string `json:"curve"`
	PeerPublicKey []byte `json:"peerPublicKey"`
	Nonce         []byte `json:"nonce"`
}

type ECDHComputeSecretResponse struct {
	PartialSecret       []byte         `json:"partialSecret"`
	PublicKeyShares     map[int][]byte `json:"publicKeyShares"`
	Proof               []byte         `json:"proof"`
	PartialSharedSecret []byte         `json:"partialSharedSecret"`
}
