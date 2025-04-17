package tsm

import (
	"net/http"
	"net/url"
)

// NullAuthenticator is used in relation to unauthenticated communication between the SDK and its MPC node.
//
// Only used internally.
type NullAuthenticator struct{}

func (NullAuthenticator) unauthorized(transport http.RoundTripper) error {
	return nil
}

func (NullAuthenticator) authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error) {
	return request, nil
}

func (a NullAuthenticator) newNode(url url.URL) (*node, error) {
	return newURLNode(url, a)
}
