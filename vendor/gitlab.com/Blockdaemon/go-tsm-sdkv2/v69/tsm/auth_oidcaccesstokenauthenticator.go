package tsm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// WithOIDCAccessTokenAuthentication returns a configuration usable for creating a TSMClient on a node which accepts
// the provided access token.
func (c Configuration) WithOIDCAccessTokenAuthentication(accessToken string) *Configuration {
	c.authenticatorBuilder = func() (*Authenticator, error) {
		authenticator := NewOIDCAccessTokenAuthenticator(accessToken)
		return &authenticator, nil
	}
	return &c
}

// OIDCAccessTokenAuthenticator is used for authenticating the SDK against an MPC node using API keys.
//
// Only used internally.
type OIDCAccessTokenAuthenticator struct {
	accessToken string
}

func NewOIDCAccessTokenAuthenticator(accessToken string) Authenticator {
	authenticator := &OIDCAccessTokenAuthenticator{
		accessToken: accessToken,
	}

	return authenticator
}

func (a OIDCAccessTokenAuthenticator) unauthorized(transport http.RoundTripper) error {
	return errors.New("unauthorized OIDC access token")
}

func (a OIDCAccessTokenAuthenticator) authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error) {
	if a.accessToken == "" {
		return nil, fmt.Errorf("unable to authenticate request, no oidc access token")
	}
	request.Header.Set("Authorization", fmt.Sprintf("OIDCAccessToken %s", a.accessToken))

	return request, nil
}

func (a OIDCAccessTokenAuthenticator) newNode(url url.URL, tlsConfig *tls.Config) (*node, error) {
	return newURLNode(url, tlsConfig, a)
}
