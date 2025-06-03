package tsm

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

// Authenticator provides internal methods related for authentication of the SDK against the MPC node.
//
// Only used internally.
type Authenticator interface {
	authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error)
	unauthorized(transport http.RoundTripper) error
	newNode(url url.URL, tlsConfig *tls.Config) (*node, error)
}
