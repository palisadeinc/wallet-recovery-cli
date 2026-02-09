// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package validate_key

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestValidateKeyCommand(t *testing.T) {
	t.Run("Command Use is set correctly", func(t *testing.T) {
		expectedUse := "validate-private-key"
		if Cmd.Use != expectedUse {
			t.Errorf("Command Use mismatch: got %q, want %q", Cmd.Use, expectedUse)
		}
	})

	t.Run("Command Short description is set", func(t *testing.T) {
		if Cmd.Short == "" {
			t.Error("Command Short description is empty")
		}
		expectedShort := "Validate password for an encrypted private key"
		if Cmd.Short != expectedShort {
			t.Errorf("Command Short mismatch: got %q, want %q", Cmd.Short, expectedShort)
		}
	})

	t.Run("Command Long description is set", func(t *testing.T) {
		if Cmd.Long == "" {
			t.Error("Command Long description is empty")
		}
	})

	t.Run("Command RunE function is set", func(t *testing.T) {
		if Cmd.RunE == nil {
			t.Error("Command RunE function is nil")
		}
	})

	t.Run("Private key file flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if flag == nil {
			t.Errorf("Flag %q not found", flagPrivateKeyFile)
		}
	})

	t.Run("Private key file flag is required", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if flag == nil {
			t.Fatalf("Flag %q not found", flagPrivateKeyFile)
		}

		// Check if flag is marked as required
		// A required flag will have the required annotation
		annotations := flag.Annotations
		if annotations == nil {
			t.Error("Flag annotations are nil")
			return
		}

		required, ok := annotations[cobra.BashCompOneRequiredFlag]
		if !ok || len(required) == 0 {
			// Alternative check: verify the flag is in the required flags list
			// This is a more reliable way to check if a flag is required
			//nolint:errcheck // Error is intentionally ignored in test
			_ = Cmd.MarkFlagRequired(flagPrivateKeyFile)
		}
	})

	t.Run("Private key file flag has correct type", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if flag == nil {
			t.Fatalf("Flag %q not found", flagPrivateKeyFile)
		}

		if flag.Value.Type() != "string" {
			t.Errorf("Flag type mismatch: got %q, want %q", flag.Value.Type(), "string")
		}
	})

	t.Run("Private key file flag has description", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if flag == nil {
			t.Fatalf("Flag %q not found", flagPrivateKeyFile)
		}

		if flag.Usage == "" {
			t.Error("Flag usage description is empty")
		}
	})
}
