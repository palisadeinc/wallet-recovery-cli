package transport

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

func SetSessionConfig(h http.Header, sessionID string, players map[int][]byte) {
	for i, k := range players {
		if len(k) > 0 {
			h.Add("MPC-Players", fmt.Sprintf("%d %s", i, base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(k)))
		} else {
			h.Add("MPC-Players", strconv.Itoa(i))
		}
	}
	h.Add("MPC-SessionID", sessionID)
}

func GetSessionConfig(h http.Header) (string, map[int][]byte, error) {
	sessionID := h.Get("MPC-SessionID")
	if sessionID == "" {
		return "", nil, fmt.Errorf("missing session ID")
	}

	players := map[int][]byte{}
	for _, v := range h.Values("MPC-Players") {
		for _, s := range strings.Split(v, ",") {
			before, after, found := strings.Cut(strings.TrimSpace(s), " ")

			playerIndex, err := strconv.Atoi(before)
			if err != nil {
				return "", nil, fmt.Errorf("invalid player index in header: %s", err)
			}

			var publicKey []byte
			if found {
				publicKey, err = base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(after)
				if err != nil {
					return "", nil, fmt.Errorf("invalid public key in header for player %d: %s", playerIndex, err)
				}
			}
			players[playerIndex] = publicKey
		}
	}

	return sessionID, players, nil
}

func GetSessionID(h http.Header) string {
	return h.Get("MPC-SessionID")
}
