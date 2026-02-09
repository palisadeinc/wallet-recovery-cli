// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package decrypt

import (
	"testing"
)

func TestDecryptCommandStructure(t *testing.T) {
	t.Run("Command Use field is set correctly", func(t *testing.T) {
		if Cmd.Use != "decrypt" {
			t.Errorf("expected Use to be 'decrypt', got '%s'", Cmd.Use)
		}
	})

	t.Run("Command Short description is set", func(t *testing.T) {
		if Cmd.Short == "" {
			t.Error("expected Short description to be set, got empty string")
		}
		expectedShort := "Decrypt an encrypted recovery private key file"
		if Cmd.Short != expectedShort {
			t.Errorf("expected Short to be '%s', got '%s'", expectedShort, Cmd.Short)
		}
	})

	t.Run("Command Long description is set", func(t *testing.T) {
		if Cmd.Long == "" {
			t.Error("expected Long description to be set, got empty string")
		}
		// Just verify it starts with the expected text and contains key sections
		if !contains(Cmd.Long, "Decrypt an encrypted private key file generated using the recover command") {
			t.Errorf("expected Long to contain expected text, got '%s'", Cmd.Long)
		}
		if !contains(Cmd.Long, "Use Cases:") {
			t.Error("expected Long to contain 'Use Cases:' section")
		}
		if !contains(Cmd.Long, "Examples:") {
			t.Error("expected Long to contain 'Examples:' section")
		}
	})

	t.Run("Command RunE function is set", func(t *testing.T) {
		if Cmd.RunE == nil {
			t.Error("expected RunE function to be set, got nil")
		}
	})
}

func TestDecryptCommandFlags(t *testing.T) {
	t.Run("encrypted-private-key-file flag exists", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncryptedPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptedPrivateKeyFile)
		}
	})

	t.Run("decrypted-output-file flag exists", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagDecryptedOutputFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagDecryptedOutputFile)
		}
	})

	t.Run("encrypted-private-key-file flag is required", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncryptedPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptedPrivateKeyFile)
			return
		}
		// Check if flag is marked as required
		annotations := f.Annotations
		if annotations == nil {
			t.Errorf("expected flag '%s' to have annotations", flagEncryptedPrivateKeyFile)
		}
	})

	t.Run("decrypted-output-file flag is required", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagDecryptedOutputFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagDecryptedOutputFile)
		}
	})

	t.Run("encrypted-private-key-file flag has correct type", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncryptedPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptedPrivateKeyFile)
			return
		}
		if f.Value.Type() != "string" {
			t.Errorf("expected flag '%s' to be string type, got %s", flagEncryptedPrivateKeyFile, f.Value.Type())
		}
	})

	t.Run("decrypted-output-file flag has correct type", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagDecryptedOutputFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagDecryptedOutputFile)
			return
		}
		if f.Value.Type() != "string" {
			t.Errorf("expected flag '%s' to be string type, got %s", flagDecryptedOutputFile, f.Value.Type())
		}
	})

	t.Run("encrypted-private-key-file flag has usage description", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncryptedPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptedPrivateKeyFile)
			return
		}
		if f.Usage == "" {
			t.Errorf("expected flag '%s' to have usage description", flagEncryptedPrivateKeyFile)
		}
	})

	t.Run("decrypted-output-file flag has usage description", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagDecryptedOutputFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagDecryptedOutputFile)
			return
		}
		if f.Usage == "" {
			t.Errorf("expected flag '%s' to have usage description", flagDecryptedOutputFile)
		}
	})
}

func TestDecryptCommandFlagDefaults(t *testing.T) {
	t.Run("encrypted-private-key-file flag default is empty", func(t *testing.T) {
		val, err := Cmd.Flags().GetString(flagEncryptedPrivateKeyFile)
		if err != nil {
			t.Errorf("unexpected error getting flag '%s': %v", flagEncryptedPrivateKeyFile, err)
			return
		}
		if val != "" {
			t.Errorf("expected flag '%s' default to be empty, got '%s'", flagEncryptedPrivateKeyFile, val)
		}
	})

	t.Run("decrypted-output-file flag default is empty", func(t *testing.T) {
		val, err := Cmd.Flags().GetString(flagDecryptedOutputFile)
		if err != nil {
			t.Errorf("unexpected error getting flag '%s': %v", flagDecryptedOutputFile, err)
			return
		}
		if val != "" {
			t.Errorf("expected flag '%s' default to be empty, got '%s'", flagDecryptedOutputFile, val)
		}
	})
}

func TestFlagConstants(t *testing.T) {
	t.Run("flagEncryptedPrivateKeyFile constant is correct", func(t *testing.T) {
		if flagEncryptedPrivateKeyFile != "encrypted-private-key-file" {
			t.Errorf("expected constant to be 'encrypted-private-key-file', got '%s'", flagEncryptedPrivateKeyFile)
		}
	})

	t.Run("flagDecryptedOutputFile constant is correct", func(t *testing.T) {
		if flagDecryptedOutputFile != "decrypted-output-file" {
			t.Errorf("expected constant to be 'decrypted-output-file', got '%s'", flagDecryptedOutputFile)
		}
	})
}

// contains is a helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
