package tsm

import (
	"encoding/base64"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/random"
	"time"
)

// SessionConfig contains information about an MPC session, including which players are participating.
type SessionConfig struct {
	sessionID      string
	players        map[int][]byte
	connectTimeout time.Duration
	sessionTimeout time.Duration
}

// NewSessionConfig creates a new SessionConfig for a given session ID. All players participating in the session must have their
// player indices specified in players. For dynamic players, i.e. players where the node does not know their public key
// in advance, their public keys must be provided in dynamicPublicKeys. If all players are static then dynamicPublicKeys
// can be nil.
func NewSessionConfig(sessionID string, players []int, dynamicPublicKeys map[int][]byte) *SessionConfig {
	return NewSessionConfigWithTimeouts(sessionID, players, dynamicPublicKeys, "", "")
}

// NewSessionConfigWithTimeouts creates a new SessionConfig for a given session ID. All players participating in the
// session must have their player indices specified in players. For dynamic players, i.e. players where the node does
// not know their public key in advance, their public keys must be provided in dynamicPublicKeys. If all players are
// static then dynamicPublicKeys can be nil. The connection and session timeout can be set for the session, but they can
// never exceed the values configured on the node. The format is a string specifying the duration, e.g. "1m30s". If the
// timeout string is invalid it will be ignored.
func NewSessionConfigWithTimeouts(sessionID string, players []int, dynamicPublicKeys map[int][]byte, connectTimeout, sessionTimeout string) *SessionConfig {
	var connectTimeoutDuration, sessionTimeoutDuration time.Duration

	if connectTimeout != "" {
		if timeoutValue, err := time.ParseDuration(connectTimeout); err == nil {
			connectTimeoutDuration = timeoutValue
		}
	}

	if sessionTimeout != "" {
		if timeoutValue, err := time.ParseDuration(sessionTimeout); err == nil {
			sessionTimeoutDuration = timeoutValue
		}
	}

	playersMap := map[int][]byte{}
	for _, i := range players {
		if dynamicPublicKeys != nil {
			playersMap[i] = dynamicPublicKeys[i]
		} else {
			playersMap[i] = nil
		}
	}
	return &SessionConfig{
		sessionID:      sessionID,
		players:        playersMap,
		connectTimeout: connectTimeoutDuration,
		sessionTimeout: sessionTimeoutDuration,
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
		sessionID:      sessionID,
		players:        players,
		connectTimeout: 0,
		sessionTimeout: 0,
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
		sessionID:      sessionID,
		players:        players,
		connectTimeout: 0,
		sessionTimeout: 0,
	}
}

func (sc SessionConfig) SessionID() string {
	return sc.sessionID
}

// GenerateSessionID generates a random session ID. All nodes must agree on the session ID when starting an MPC operation.
func GenerateSessionID() string {
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(random.Bytes(32))
}
