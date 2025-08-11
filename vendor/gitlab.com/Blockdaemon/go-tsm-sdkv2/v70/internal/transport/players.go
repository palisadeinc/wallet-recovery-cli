package transport

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func SetSessionConfig(h http.Header, sessionID string, players map[int][]byte, connectTimeout, sessionTimeout time.Duration) {
	h.Add("MPC-SessionID", sessionID)

	for i, k := range players {
		if len(k) > 0 {
			h.Add("MPC-Players", fmt.Sprintf("%d %s", i, base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k)))
		} else {
			h.Add("MPC-Players", strconv.Itoa(i))
		}
	}

	if connectTimeout > 0 {
		h.Add("MPC-ConnectTimeout", strconv.FormatInt(int64(connectTimeout), 10))
	}

	if sessionTimeout > 0 {
		h.Add("MPC-SessionTimeout", strconv.FormatInt(int64(sessionTimeout), 10))
	}
}

func GetSessionConfig(h http.Header) (sessionID string, players map[int][]byte, connectTimeout time.Duration, sessionTimeout time.Duration, err error) {
	sessionID = h.Get("MPC-SessionID")
	if sessionID == "" {
		return "", nil, 0, 0, fmt.Errorf("missing session ID")
	}

	players = map[int][]byte{}
	for _, v := range h.Values("MPC-Players") {
		for _, s := range strings.Split(v, ",") {
			before, after, found := strings.Cut(strings.TrimSpace(s), " ")

			playerIndex, err := strconv.Atoi(before)
			if err != nil {
				return "", nil, 0, 0, fmt.Errorf("invalid player index in header: %s", err)
			}

			var publicKey []byte
			if found {
				publicKey, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(after)
				if err != nil {
					return "", nil, 0, 0, fmt.Errorf("invalid public key in header for player %d: %s", playerIndex, err)
				}
			}
			players[playerIndex] = publicKey
		}
	}

	if connectTimeoutString := h.Get("MPC-ConnectTimeout"); connectTimeoutString != "" {
		if timeoutValue, err := strconv.ParseInt(connectTimeoutString, 10, 64); err == nil {
			connectTimeout = time.Duration(timeoutValue)
		}
	}

	if sessionTimeoutString := h.Get("MPC-SessionTimeout"); sessionTimeoutString != "" {
		if timeoutValue, err := strconv.ParseInt(sessionTimeoutString, 10, 64); err == nil {
			sessionTimeout = time.Duration(timeoutValue)
		}
	}

	return sessionID, players, connectTimeout, sessionTimeout, nil
}

func GetSessionID(h http.Header) string {
	return h.Get("MPC-SessionID")
}
