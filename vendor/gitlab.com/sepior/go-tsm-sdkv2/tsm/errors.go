package tsm

import (
	"errors"
	"fmt"
	"io"
	"net/http"
)

// tsmError is an unexported type that ensures that only (wrapped) api supported errors escapes the sdk
// tsmErrors should always be wrapped to prevent users of the sdk to use == on a specific tsmError. That
// would break code if we were to wrap a tsmError with more information in the future
type tsmError string

func (te tsmError) Error() string {
	return string(te)
}

// WrapWith returns an error that wraps te and the info of err.
// err itself is not wrapped since we don't want users of the sdk to rely on other error types
func (te tsmError) WrapWith(err error) error {
	return fmt.Errorf("%w: %s", te, err)
}

const ErrAuthentication = tsmError("tsm authentication failed")
const ErrAccess = tsmError("tsm access denied")
const ErrInvalidInput = tsmError("invalid tsm input")
const ErrUnavailable = tsmError("tsm temporarily unavailable")
const ErrOperationFailed = tsmError("tsm operation failed")

// toTSMError returns a wrapped tsmError. if err is a (wrapped) tsmError err is returned.
// otherwise an error is returned that wraps fallback and the info of err
func toTSMError(err error, fallback tsmError) error {
	if err == nil {
		return nil
	}
	var te interface {
		WrapWith(err error) error
	}
	isTsmError := errors.As(err, &te)
	if isTsmError {
		return err
	}
	return fallback.WrapWith(err)
}

func wrapWithSessionID(fallback tsmError, err error, sessionID string) error {
	return fmt.Errorf("%w sessionID=%s", toTSMError(err, fallback), sessionID)
}

// returns nil or a wrapped tsmError
func checkStatusCode(response *http.Response) error {
	switch s := response.StatusCode; {
	case s >= 200 && s < 300:
		return nil
	case s == 401:
		return wrapAsError(ErrAuthentication, response)
	case s == 403:
		return wrapAsError(ErrAccess, response)
	case s >= 400 && s < 500:
		return wrapAsError(ErrInvalidInput, response)
	case s == 503:
		return wrapAsError(ErrUnavailable, response)
	default:
		return wrapAsError(ErrOperationFailed, response)
	}
}

func wrapAsError(sentinel tsmError, response *http.Response) error {
	reason, _ := io.ReadAll(response.Body)
	return fmt.Errorf("%w ; node returned %d: %s", sentinel, response.StatusCode, reason)
}
