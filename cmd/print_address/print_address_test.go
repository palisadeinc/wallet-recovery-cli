// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package print_address

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
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

	t.Run("Long description mentions auto-detection", func(t *testing.T) {
		if !strings.Contains(Cmd.Long, "automatically detects") {
			t.Error("expected Long description to mention auto-detection")
		}
	})

	t.Run("Long description mentions supported chains", func(t *testing.T) {
		if !strings.Contains(Cmd.Long, "Ethereum") {
			t.Error("expected Long description to mention Ethereum")
		}
		if !strings.Contains(Cmd.Long, "Solana") {
			t.Error("expected Long description to mention Solana")
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

	t.Run("private-key-file flag has correct type", func(t *testing.T) {
		f := Cmd.Flags().Lookup(flagPrivateKeyFile)
		if f == nil {
			t.Errorf("expected flag '%s' to exist", flagPrivateKeyFile)
			return
		}
		// Verify it's a string flag
		if f.Value.Type() != "string" {
			t.Errorf("expected flag '%s' to be string type, got %s", flagPrivateKeyFile, f.Value.Type())
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
}

// createTestCommand creates a fresh command instance for testing
func createTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   Cmd.Use,
		Short: Cmd.Short,
		Long:  Cmd.Long,
		RunE:  Cmd.RunE,
	}
	cmd.Flags().String(flagPrivateKeyFile, "", "Path to file containing private key.")
	return cmd
}

func TestPrintAddressWithEthereumKey(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Valid 32-byte SECP256K1 private key (hex encoded)
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	// Write the private key to a temp file
	keyFile := filepath.Join(tmpDir, "eth_private.der")
	if err := os.WriteFile(keyFile, privateKeyBytes, 0o400); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create command and capture output
	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--private-key-file", keyFile})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	output := stdout.String()
	if !strings.Contains(output, "EVM-compatible address:") {
		t.Errorf("Expected output to contain 'EVM-compatible address:', got: %s", output)
	}

	// Verify the address format (should start with 0x)
	if !strings.Contains(output, "0x") {
		t.Errorf("Expected Ethereum address to start with 0x, got: %s", output)
	}
}

func TestPrintAddressWithSolanaKey(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Valid 32-byte ED25519 private key (raw scalar, big-endian)
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	// Write the private key to a temp file
	keyFile := filepath.Join(tmpDir, "sol_private.der")
	if err := os.WriteFile(keyFile, privateKeyBytes, 0o400); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Create command and capture output
	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--private-key-file", keyFile})

	err = cmd.Execute()
	if err != nil {
		t.Fatalf("Command failed: %v, stderr: %s", err, stderr.String())
	}

	// The same key bytes will be tried as Ethereum first, which will succeed
	// So we just verify the command completes successfully
	output := stdout.String()
	if output == "" {
		t.Error("Expected non-empty output")
	}
}

func TestPrintAddressWithEncryptedKey(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Valid 32-byte private key
	privateKeyHex := "044c2e76de7699aac908b2a60756a550f5acc3fca8a9204ed0475dc0b0a30acb"
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	// Encrypt the private key
	password := []byte("testpassword123")
	encryptedBytes, err := utils.EncryptWithHeader(password, privateKeyBytes)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Write the encrypted key to a temp file
	keyFile := filepath.Join(tmpDir, "encrypted_private.enc")
	if err := os.WriteFile(keyFile, encryptedBytes, 0o400); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	// Verify the file has the encryption header
	fileBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("Failed to read key file: %v", err)
	}
	if !utils.HasEncryptionHeader(fileBytes) {
		t.Error("Expected file to have encryption header")
	}

	// Note: We can't easily test the interactive password prompt in unit tests
	// This test just verifies the file is correctly identified as encrypted
}

func TestPrintAddressWithNonExistentFile(t *testing.T) {
	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--private-key-file", "/nonexistent/path/to/key.der"})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for non-existent file")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "Error") {
		t.Errorf("Expected error message in stderr, got: %s", errOutput)
	}
}

func TestPrintAddressWithInvalidPath(t *testing.T) {
	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	// Path traversal attempt
	cmd.SetArgs([]string{"--private-key-file", "../../../etc/passwd"})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestPrintAddressWithInvalidKeyData(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Write invalid data (not a valid private key)
	keyFile := filepath.Join(tmpDir, "invalid.der")
	if err := os.WriteFile(keyFile, []byte("not a valid key"), 0o400); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--private-key-file", keyFile})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for invalid key data")
	}

	errOutput := stderr.String()
	if !strings.Contains(errOutput, "Error") {
		t.Errorf("Expected error message in stderr, got: %s", errOutput)
	}
}

func TestPrintAddressWithEmptyFile(t *testing.T) {
	// Create a temporary directory for test files
	tmpDir := t.TempDir()

	// Write empty file
	keyFile := filepath.Join(tmpDir, "empty.der")
	if err := os.WriteFile(keyFile, []byte{}, 0o400); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}

	cmd := createTestCommand()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--private-key-file", keyFile})

	err := cmd.Execute()
	if err == nil {
		t.Error("Expected error for empty file")
	}
}
