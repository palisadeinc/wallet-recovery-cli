package utils

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
)

func OpenReadOnlyFile(filepath string) ([]byte, error) {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return nil, errors.WithMessage(err, "file does not exist")
	}

	f, err := os.OpenFile(filepath, os.O_RDONLY, 0400)
	if err != nil {
		return nil, errors.WithMessage(err, "error opening file")
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, errors.WithMessage(err, "error reading file")
	}

	return content, nil
}

func WriteToFile(filepath string, content []byte) error {
	f, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return errors.WithMessage(err, "error opening file")
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	_, err = f.Write(content)
	if err != nil {
		return errors.WithMessage(err, "error writing to file")
	}

	return nil
}
