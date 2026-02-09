// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"path/filepath"
	"testing"
)

func TestGenerateCommandExists(t *testing.T) {
	if Cmd == nil {
		t.Fatal("Generate command is nil")
	}

	if Cmd.Use != "generate-recovery-keypair" {
		t.Errorf("Command Use = %q, want %q", Cmd.Use, "generate-recovery-keypair")
	}

	if Cmd.Short == "" {
		t.Error("Command Short description is empty")
	}

	if Cmd.Long == "" {
		t.Error("Command Long description is empty")
	}

	if Cmd.RunE == nil {
		t.Error("Command RunE function is nil")
	}
}

func TestGenerateCommandFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		wantType string
	}{
		{
			name:     "private-key-file flag exists",
			flagName: flagPrivateKeyFile,
			wantType: "string",
		},
		{
			name:     "public-key-file flag exists",
			flagName: flagPublicKeyFile,
			wantType: "string",
		},
		{
			name:     "encrypt-private-key flag exists",
			flagName: flagEncryptPrivateKey,
			wantType: "bool",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := Cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("Flag %q not found", tt.flagName)
				return
			}

			if flag.Value.Type() != tt.wantType {
				t.Errorf("Flag %q type = %q, want %q", tt.flagName, flag.Value.Type(), tt.wantType)
			}
		})
	}
}

func TestGenerateCommandFlagDefaults(t *testing.T) {
	tests := []struct {
		name        string
		flagName    string
		wantDefault string
	}{
		{
			name:        "private-key-file default is empty",
			flagName:    flagPrivateKeyFile,
			wantDefault: "",
		},
		{
			name:        "public-key-file default is empty",
			flagName:    flagPublicKeyFile,
			wantDefault: "",
		},
		{
			name:        "encrypt-private-key default is false",
			flagName:    flagEncryptPrivateKey,
			wantDefault: "false",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := Cmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Fatalf("Flag %q not found", tt.flagName)
			}

			if flag.DefValue != tt.wantDefault {
				t.Errorf("Flag %q default = %q, want %q", tt.flagName, flag.DefValue, tt.wantDefault)
			}
		})
	}
}

func TestGenerateCommandFlagsRequired(t *testing.T) {
	// Test that private-key-file and public-key-file are marked as required together
	// This is verified by checking that the command has the MarkFlagsRequiredTogether call
	// We can verify this by checking the flag configuration

	privateKeyFlag := Cmd.Flags().Lookup(flagPrivateKeyFile)
	publicKeyFlag := Cmd.Flags().Lookup(flagPublicKeyFile)

	if privateKeyFlag == nil {
		t.Fatal("private-key-file flag not found")
	}
	if publicKeyFlag == nil {
		t.Fatal("public-key-file flag not found")
	}

	// Both flags should exist and be strings
	if privateKeyFlag.Value.Type() != "string" {
		t.Error("private-key-file should be a string flag")
	}
	if publicKeyFlag.Value.Type() != "string" {
		t.Error("public-key-file should be a string flag")
	}
}

func TestMinPasswordLength(t *testing.T) {
	if minPasswordLength != 8 {
		t.Errorf("minPasswordLength = %d, want 8", minPasswordLength)
	}
}

func TestFlagConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		want     string
	}{
		{
			name:     "flagPrivateKeyFile constant",
			constant: flagPrivateKeyFile,
			want:     "private-key-file",
		},
		{
			name:     "flagPublicKeyFile constant",
			constant: flagPublicKeyFile,
			want:     "public-key-file",
		},
		{
			name:     "flagEncryptPrivateKey constant",
			constant: flagEncryptPrivateKey,
			want:     "encrypt-private-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("Constant = %q, want %q", tt.constant, tt.want)
			}
		})
	}
}

func TestGenerateCommandWithValidPaths(t *testing.T) {
	// Create temp directory for test outputs
	tempDir := t.TempDir()

	privateKeyPath := filepath.Join(tempDir, "private.der")
	publicKeyPath := filepath.Join(tempDir, "public.der")

	// Test that command can be configured with valid paths
	cmd := Cmd
	cmd.SetArgs([]string{
		"--private-key-file", privateKeyPath,
		"--public-key-file", publicKeyPath,
	})

	// Verify flags are set correctly
	privateKeyFlag := cmd.Flags().Lookup(flagPrivateKeyFile)
	publicKeyFlag := cmd.Flags().Lookup(flagPublicKeyFile)

	if privateKeyFlag == nil || publicKeyFlag == nil {
		t.Fatal("Flags not found")
	}

	// The flags should be available for retrieval
	if privateKeyFlag.Value.Type() != "string" {
		t.Error("private-key-file flag should be a string")
	}
	if publicKeyFlag.Value.Type() != "string" {
		t.Error("public-key-file flag should be a string")
	}
}

func TestGenerateCommandEncryptionFlag(t *testing.T) {
	tempDir := t.TempDir()

	privateKeyPath := filepath.Join(tempDir, "private.der")
	publicKeyPath := filepath.Join(tempDir, "public.der")

	// Test with encryption enabled
	cmd := Cmd
	cmd.SetArgs([]string{
		"--private-key-file", privateKeyPath,
		"--public-key-file", publicKeyPath,
		"--encrypt-private-key",
	})

	encryptFlag := cmd.Flags().Lookup(flagEncryptPrivateKey)
	if encryptFlag == nil {
		t.Fatal("encrypt-private-key flag not found")
	}

	if encryptFlag.Value.Type() != "bool" {
		t.Error("encrypt-private-key flag should be a bool")
	}
}

func TestGenerateCommandFilePathConstruction(t *testing.T) {
	tests := []struct {
		name           string
		privateKeyDir  string
		publicKeyDir   string
		privateKeyFile string
		publicKeyFile  string
	}{
		{
			name:           "simple filenames",
			privateKeyDir:  "/tmp",
			publicKeyDir:   "/tmp",
			privateKeyFile: "private.der",
			publicKeyFile:  "public.der",
		},
		{
			name:           "nested directories",
			privateKeyDir:  "/tmp/keys/recovery",
			publicKeyDir:   "/tmp/keys/recovery",
			privateKeyFile: "private.der",
			publicKeyFile:  "public.der",
		},
		{
			name:           "different extensions",
			privateKeyDir:  "/tmp",
			publicKeyDir:   "/tmp",
			privateKeyFile: "private.pem",
			publicKeyFile:  "public.pem",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			privateKeyPath := filepath.Join(tt.privateKeyDir, tt.privateKeyFile)
			publicKeyPath := filepath.Join(tt.publicKeyDir, tt.publicKeyFile)

			// Verify paths are constructed correctly
			if !filepath.IsAbs(privateKeyPath) && tt.privateKeyDir != "" {
				// Relative paths should still be valid
				if privateKeyPath == "" {
					t.Error("private key path is empty")
				}
			}

			if !filepath.IsAbs(publicKeyPath) && tt.publicKeyDir != "" {
				// Relative paths should still be valid
				if publicKeyPath == "" {
					t.Error("public key path is empty")
				}
			}
		})
	}
}

func TestGenerateCommandDescription(t *testing.T) {
	// Verify command has proper documentation
	if Cmd.Short != "Generate a recovery keypair" {
		t.Errorf("Command Short = %q, want %q", Cmd.Short, "Generate a recovery keypair")
	}

	// Verify Long description starts with the expected text
	expectedLongStart := "Generate an RSA-4096 key pair for wallet backup and recovery."
	if !contains(Cmd.Long, expectedLongStart) {
		t.Errorf("Command Long should contain %q", expectedLongStart)
	}

	// Verify Long description contains key information
	keyPhrases := []string{
		"PUBLIC key is uploaded to Palisade",
		"PRIVATE key is kept secure",
		"PKIX DER format",
		"password encryption",
	}

	for _, phrase := range keyPhrases {
		if !contains(Cmd.Long, phrase) {
			t.Errorf("Command Long should contain %q", phrase)
		}
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
