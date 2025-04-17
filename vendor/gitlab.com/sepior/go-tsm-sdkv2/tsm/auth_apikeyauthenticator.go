package tsm

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// WithAPIKeyAuthentication returns a configuration usable for creating a TSMClient on a node which accepts the provided apiKey.
func (c Configuration) WithAPIKeyAuthentication(apiKey string) *Configuration {
	authenticator := NewAPIKeyAuthenticator(apiKey)
	c.authenticator = &authenticator
	return &c
}

// APIKeyAuthenticator is used for authenticating the SDK against an MPC node using API keys.
//
// Only used internally.
type APIKeyAuthenticator struct {
	apiKey string
}

func NewAPIKeyAuthenticator(apiKey string) Authenticator {
	return APIKeyAuthenticator{apiKey: apiKey}
}

func (a APIKeyAuthenticator) unauthorized(transport http.RoundTripper) error {
	return errors.New("unauthorized API key")
}

func (a APIKeyAuthenticator) authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error) {
	if a.apiKey == "" {
		return nil, errors.New("no API key has been set")
	}
	request.Header.Set("Authorization", fmt.Sprintf("APIKEY %s", a.apiKey))
	return request, nil
}

func (a APIKeyAuthenticator) newNode(url url.URL) (*node, error) {
	return newURLNode(url, a)
}
