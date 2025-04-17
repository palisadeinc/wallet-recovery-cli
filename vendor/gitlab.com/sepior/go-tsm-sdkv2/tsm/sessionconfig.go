package tsm

import (
	"encoding/base64"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/random"
)

// SessionConfig contains information about an MPC session, including which players are participating.
type SessionConfig struct {
	sessionID string
	players   map[int][]byte
}

// NewSessionConfig creates a new SessionConfig for a given session ID. All players participating in the session must have their
// player indices specified in players. For dynamic players, i.e. players where the node does not know their public key
// in advance, their public keys must be provided in dynamicPublicKeys. If all players are static then dynamicPublicKeys
// can be nil.
func NewSessionConfig(sessionID string, players []int, dynamicPublicKeys map[int][]byte) *SessionConfig {
	playersMap := map[int][]byte{}
	for _, i := range players {
		if dynamicPublicKeys != nil {
			playersMap[i] = dynamicPublicKeys[i]
		} else {
			playersMap[i] = nil
		}
	}
	return &SessionConfig{
		sessionID: sessionID,
		players:   playersMap,
	}
}

// NewStaticSessionConfig creates a new SessionConfig for a given session ID where all players are static, meaning that their
// public keys are known by the nodes. Players are numbered from 0 up to playerCount-1.
func NewStaticSessionConfig(sessionID string, playerCount int) *SessionConfig {
	players := map[int][]byte{}
	for i := 0; i < playerCount; i++ {
		players[i] = nil
	}
	return &SessionConfig{
		sessionID: sessionID,
		players:   players,
	}
}

// NewStaticSessionConfigWithTenant creates a new SessionConfig for a given session ID where all players, except player 0, are
// static, meaning that their public keys are known by the nodes. The public key of player 0 must be provided in
// tenantPublicKey and all players are numbered from 0 up to playerCount-1.
func NewStaticSessionConfigWithTenant(sessionID string, playerCount int, tenantPublicKey []byte) *SessionConfig {
	players := map[int][]byte{}
	for i := 0; i < playerCount; i++ {
		if i == 0 {
			players[i] = tenantPublicKey
		} else {
			players[i] = nil
		}
	}
	return &SessionConfig{
		sessionID: sessionID,
		players:   players,
	}
}

func (sc SessionConfig) SessionID() string {
	return sc.sessionID
}

// GenerateSessionID generates a random session ID. All nodes must agree on the session ID when starting an MPC operation.
func GenerateSessionID() string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(random.Bytes(32))
}
