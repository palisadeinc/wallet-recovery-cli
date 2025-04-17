package transport

type UserInput struct {
	DisplayName string `json:"display_name"`
	Description string `json:"description"`
}

type Password struct {
	Password string `json:"password"`
}

// ProtocolInfo contains information about the MCP protocols that are used for each of the
// algorithms supported by the TSM.
//
// For example, the algorithm ECDSA can have a protocol name of 10 = DKLS19. This means that
// ECDSA threshold signatures are computed using the DKLS19 MPC protocol.
type ProtocolInfo struct {
	ECDSA     ProtocolName `json:"ecdsa"`
	SCHNORR   ProtocolName `json:"schnorr"`
	ECDH      ProtocolName `json:"ecdh"`
	SEPPRF    ProtocolName `json:"prf"`
	RSA       ProtocolName `json:"rsa"`
	AES       ProtocolName `json:"aes"`
	HMAC      ProtocolName `json:"hmac"`
	AN10922   ProtocolName `json:"an10922"`
	BROADCAST ProtocolName `json:"broadcast"`
	RFC5649   ProtocolName `json:"rfc5649"`
}

type Version struct {
	Version             string `json:"version"`
	ClientAPI           string `json:"clientapi"`
	ClientCommunication string `json:"clientcommunication"`
	NodeCommunication   string `json:"nodecommunication"`
	NodeConfiguration   string `json:"nodeconfiguration"`
}

type OIDCInitReturnValues struct {
	Timestamp int64  `json:"timestamp"`
	Nonce     []byte `json:"nonce"`
	MAC       []byte `json:"mac"`
}

type OIDCEndRequestBody struct {
	Timestamp int64  `json:"timestamp"`
	Nonces    []byte `json:"nonces"`
	MAC       []byte `json:"mac"`
	IDToken   string `json:"idToken"`
	Hash      string `json:"hash"`
}

type OIDCAccessTokenRequestBody struct {
	AccessToken string `json:"accessToken"`
}

type BearerToken struct {
	Token string `json:"token"`
}

type HealthInformation struct {
	PendingAuditLogEntries int `json:"pending_audit_log_entries"`
}
