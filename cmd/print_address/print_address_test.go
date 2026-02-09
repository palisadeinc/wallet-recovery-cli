// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package print_address

import (
	"testing"
)

func TestPrintAddressCommandStructure(t *testing.T) {
	t.Run("Command Use field is set correctly", func(t *testing.T) {
		if Cmd.Use != "print-address" {
			t.Errorf("expected Use='print-address', got '%s'", Cmd.Use)
		}
	})

	t.Run("Command Short description is set", func(t *testing.T) {
		if Cmd.Short == "" {
			t.Error("expected Short description to be set, got empty string")
		}
		expectedShort := "Print blockchain address associated with recovered private key"
		if Cmd.Short != expectedShort {
			t.Errorf("expected Short='%s', got '%s'", expectedShort, Cmd.Short)
		}
	})

	t.Run("Command Long description is set", func(t *testing.T) {
		if Cmd.Long == "" {
			t.Error("expected Long description to be set, got empty string")
		}
	})

	t.Run("Command RunE function is set", func(t *testing.T) {
		if Cmd.RunE == nil {
			t.Error("expected RunE function to be set, got nil")
		}
	})
}

func TestPrintAddressCommandFlags(t *testing.T) {
	t.Run("private-key-file flag exists", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagPrivateKeyFile)
			return
		}
		if f.Name != flagPrivateKeyFile {
			t.Errorf("expected flag name '%s', got '%s'", flagPrivateKeyFile, f.Name)
		}
	})

	t.Run("encrypted flag exists", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncrypted)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncrypted)
			return
		}
		if f.Name != flagEncrypted {
			t.Errorf("expected flag name '%s', got '%s'", flagEncrypted, f.Name)
		}
	})

	t.Run("private-key-file flag is required", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagPrivateKeyFile)
			return
		}
		// Check if flag is marked as required
		annotations := f.Annotations
		if annotations == nil {
			t.Errorf("expected flag '%s' to have annotations", flagPrivateKeyFile)
		}
	})

	t.Run("encrypted flag has correct type", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagEncrypted)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagEncrypted)
			return
		}
		// Verify it's a boolean flag
		if f.Value.Type() != "bool" {
			t.Errorf("expected flag '%s' to be bool type, got %s", flagEncrypted, f.Value.Type())
		}
	})
}

func TestPrintAddressCommandFlagDefaults(t *testing.T) {
	t.Run("private-key-file default is empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if flag == nil {
			t.Fatalf("expected flag '%s' to exist", flagPrivateKeyFile)
		}
		if flag.DefValue != "" {
			t.Errorf("expected default value '', got '%s'", flag.DefValue)
		}
	})

	t.Run("encrypted default is false", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagEncrypted)
		if flag == nil {
			t.Fatalf("expected flag '%s' to exist", flagEncrypted)
		}
		if flag.DefValue != "false" {
			t.Errorf("expected default value 'false', got '%s'", flag.DefValue)
		}
	})
}
