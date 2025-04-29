package utils

import (
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
)

func OpenFile(filepath string) ([]byte, error) {
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
