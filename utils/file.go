// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0
//

package utils

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// ValidateFilePath validates that a file path is not empty and doesn't contain suspicious patterns
func ValidateFilePath(path string) error {
	if path == "" {
		return fmt.Errorf("file path cannot be empty")
	}

	// Check for null bytes which could indicate path traversal attempts
	if strings.Contains(path, "\x00") {
		return fmt.Errorf("file path contains null bytes")
	}

	// Resolve to absolute path to detect path traversal attempts
	absPath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("invalid file path: %w", err)
	}

	// Ensure the path doesn't try to escape the current directory via ..
	// by checking if the resolved path is within expected bounds
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("cannot determine current working directory: %w", err)
	}

	// Allow paths that are either in current directory or absolute paths
	// but prevent suspicious patterns
	if strings.Contains(path, "..") {
		// Only allow .. if it resolves to a valid location
		// This is a basic check; more sophisticated validation could be added
		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			// Path might not exist yet, which is OK for output files
			// Just ensure it doesn't contain suspicious patterns
			if !strings.HasPrefix(absPath, cwd) && !filepath.IsAbs(path) {
				return fmt.Errorf("file path attempts to escape current directory")
			}
		} else {
			if !strings.HasPrefix(realPath, cwd) && !filepath.IsAbs(path) {
				return fmt.Errorf("file path attempts to escape current directory")
			}
		}
	}

	return nil
}

func OpenReadOnlyFile(filePath string) ([]byte, error) {
	if err := ValidateFilePath(filePath); err != nil {
		return nil, err
	}

	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %w", err)
	}

	f, err := os.OpenFile(filePath, os.O_RDONLY, 0o400)
	if err != nil {
		return nil, fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	content, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	return content, nil
}

func WriteToFile(filePath string, content []byte) error {
	if err := ValidateFilePath(filePath); err != nil {
		return err
	}

	f, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	_, err = f.Write(content)
	if err != nil {
		return fmt.Errorf("error writing to file: %w", err)
	}

	return nil
}

// ValidateUUID validates that a string is a valid UUID format
func ValidateUUID(uuidStr, fieldName string) error {
	if uuidStr == "" {
		return fmt.Errorf("%s cannot be empty", fieldName)
	}

	if _, err := uuid.Parse(uuidStr); err != nil {
		return fmt.Errorf("invalid %s format: %s (expected UUID format like 550e8400-e29b-41d4-a716-446655440000)", fieldName, uuidStr)
	}

	return nil
}

// ValidateKeyType validates that a key type is one of the allowed values
func ValidateKeyType(keyType string) error {
	if keyType == "" {
		return fmt.Errorf("key type cannot be empty")
	}

	allowedTypes := map[string]bool{
		"SECP256K1": true,
		"ED25519":   true,
	}

	if !allowedTypes[keyType] {
		return fmt.Errorf("invalid key type: %s (allowed values: SECP256K1, ED25519)", keyType)
	}

	return nil
}
