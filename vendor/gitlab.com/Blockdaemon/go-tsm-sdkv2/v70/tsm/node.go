package tsm

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/transport"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/version"
	"golang.org/x/sync/errgroup"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

type requestSender interface {
	SendRequest(r *http.Request) (*http.Response, error)
}

type requestSenderFunc func(r *http.Request) (*http.Response, error)

func (h requestSenderFunc) SendRequest(r *http.Request) (*http.Response, error) {
	return h(r)
}

type middleware func(handler requestSender) requestSender

type node struct {
	transport     http.RoundTripper
	authenticator Authenticator
	info          transport.ProtocolInfo
}

func newNode(transport http.RoundTripper, authenticator Authenticator) (*node, error) {
	n := &node{
		transport:     transport,
		authenticator: authenticator,
	}

	var nodeVersion VersionInformation

	var eg errgroup.Group

	eg.Go(func() error {
		var err error
		n.info, err = n.protocolInfo()
		return err
	})

	eg.Go(func() error {
		var err error
		nodeVersion, err = n.nodeVersion()
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, err
	}

	sdkVersion := &VersionInformation{
		Version:             version.TSM,
		ClientAPI:           version.CLIENT_API,
		ClientCommunication: version.CLIENT_COMMUNICATION,
		NodeCommunication:   version.NODE_COMMUNICATION,
		NodeConfiguration:   version.NODE_CONFIGURATION,
	}

	checkVersionCompatibility(sdkVersion, &nodeVersion)

	return n, nil
}

func newURLNode(baseURL url.URL, tlsConfig *tls.Config, authenticator Authenticator) (*node, error) {
	tlsTransport := http.DefaultTransport.(*http.Transport).Clone()
	tlsTransport.TLSClientConfig = tlsConfig
	return newNode(baseURLRoundTripper{tlsTransport, baseURL}, authenticator)
}

func (n *node) sendRequest(r *http.Request) (*http.Response, error) {
	return n.transport.RoundTrip(r)
}

func (n *node) sendAuthenticatedRequest(r *http.Request) (*http.Response, error) {
	authenticatedRequest, err := n.authenticator.authenticateRequest(r, n.transport)
	if err != nil {
		return nil, err
	}
	return n.sendRequest(authenticatedRequest)
}

// returns a (wrapped) tsmError in case of error
func (n *node) call(ctx context.Context, httpMethod string, path string, sessionConfig *SessionConfig, requestSenderFunc requestSenderFunc, inputBuilder func() interface{}) (io.Reader, error) {
	var rSender requestSender
	if sessionConfig.sessionID != "" {
		if err := validateSessionID(sessionConfig.sessionID); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrInvalidInput, err)
		}
		rSender = insertSessionConfigMiddleware(sessionConfig)(requestSenderFunc)
	} else {
		rSender = requestSender(requestSenderFunc)
	}

	f := func() (*http.Response, error) {
		var data io.Reader = nil
		isJson := false
		if inputBuilder != nil {
			input := inputBuilder()
			switch t := input.(type) {
			case io.Reader:
				data = t
			case string:
				data = strings.NewReader(t)
			default:
				isJson = true
				var err error
				data, err = marshalJSON(input)
				if err != nil {
					return nil, toTSMError(err, ErrOperationFailed)
				}
			}
		}
		request, err := http.NewRequestWithContext(ctx, httpMethod, path, data)
		if err != nil {
			return nil, toTSMError(err, ErrOperationFailed)
		}
		if isJson {
			request.Header.Set("Content-Type", "application-type/json")
		}
		return rSender.SendRequest(request)
	}

	response, err := f()
	if err != nil {
		if errors.Is(err, ErrAuthentication) {
			return nil, wrapWithSessionID(ErrAuthentication, err, sessionConfig.sessionID)
		}
		return nil, wrapWithSessionID(ErrOperationFailed, err, sessionConfig.sessionID)
	}
	// retry in case of expired tokens etc.
	if response.StatusCode == http.StatusUnauthorized {
		_, _ = io.Copy(io.Discard, response.Body)
		closeResponseBody(response)

		err = n.Unauthorized()
		if err != nil {
			return nil, wrapWithSessionID(ErrAuthentication, err, sessionConfig.sessionID)
		}

		response, err = f()
		if err != nil {
			return nil, wrapWithSessionID(ErrOperationFailed, err, sessionConfig.sessionID)
		}
	}
	defer closeResponseBody(response)
	err = checkStatusCode(response)
	if err != nil {
		return nil, wrapWithSessionID(ErrOperationFailed, err, sessionConfig.sessionID)
	}
	b, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, wrapWithSessionID(ErrOperationFailed, err, sessionConfig.sessionID)
	}
	return bytes.NewReader(b), nil
}

func (n *node) protocolInfo() (transport.ProtocolInfo, error) {
	response, err := n.call(context.TODO(), http.MethodGet, "/info/protocols", &SessionConfig{}, n.sendAuthenticatedRequest, nil)
	if err != nil {
		return transport.ProtocolInfo{}, fmt.Errorf("unable to fetch protocol information: %w", err)
	}

	var jsonResponse transport.ProtocolInfo
	if err = unmarshalJSON(response, &jsonResponse); err != nil {
		return transport.ProtocolInfo{}, fmt.Errorf("unable to parse protocol information: %w", err)
	}

	return jsonResponse, nil
}

func (n *node) nodeVersion() (VersionInformation, error) {
	response, err := n.call(context.TODO(), http.MethodGet, "/version", &SessionConfig{}, n.sendAuthenticatedRequest, nil)
	if err != nil {
		return VersionInformation{}, fmt.Errorf("unable to fetch version information: %w", err)
	}

	var jsonResponse transport.Version
	if err = unmarshalJSON(response, &jsonResponse); err != nil {
		return VersionInformation{}, fmt.Errorf("unable to parse version information: %w", err)
	}

	tsmVersion := VersionInformation(jsonResponse)

	return tsmVersion, nil
}

func (n *node) Unauthorized() error {
	return n.authenticator.unauthorized(n.transport)
}

func (n *node) URL() url.URL {
	urlRoundTripper, ok := n.transport.(baseURLRoundTripper)
	if !ok {
		return url.URL{}
	}
	return urlRoundTripper.baseURL
}

func insertSessionConfigMiddleware(sessionConfig *SessionConfig) middleware {
	return func(handler requestSender) requestSender {
		return requestSenderFunc(func(r *http.Request) (*http.Response, error) {
			transport.SetSessionConfig(r.Header, sessionConfig.sessionID, sessionConfig.players, sessionConfig.connectTimeout, sessionConfig.sessionTimeout)
			return handler.SendRequest(r)
		})
	}
}

type baseURLRoundTripper struct {
	inner   http.RoundTripper
	baseURL url.URL
}

func (b baseURLRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	r.URL.Scheme = b.baseURL.Scheme
	r.URL.Host = b.baseURL.Host
	r.URL.Path = path.Join(b.baseURL.Path, r.URL.Path)

	return b.inner.RoundTrip(r)
}

var allowedCharsInSessionID = regexp.MustCompile(`^[a-zA-Z0-9_\-]+$`).MatchString

func validateSessionID(sessionID string) error {
	if len(sessionID) > 128 {
		return fmt.Errorf("session ID must not be longer than 128 characters, but it was %d", len(sessionID))
	}
	if !allowedCharsInSessionID(sessionID) {
		return fmt.Errorf("session ID contains invalid characters: %s", sessionID)
	}
	return nil
}
