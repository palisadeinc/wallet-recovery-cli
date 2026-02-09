// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package recover

import (
	"testing"
)

func TestRecoverCommandStructure(t *testing.T) {
	t.Run("Command Use is set correctly", func(t *testing.T) {
		if Cmd.Use != "recover" {
			t.Errorf("expected Use to be 'recover', got '%s'", Cmd.Use)
		}
	})

	t.Run("Command Short description is set", func(t *testing.T) {
		if Cmd.Short == "" {
			t.Error("expected Short description to be set, got empty string")
		}
	})

	t.Run("Command Short description matches expected value", func(t *testing.T) {
		expected := "Recover a private key from recovery data"
		if Cmd.Short != expected {
			t.Errorf("expected Short to be '%s', got '%s'", expected, Cmd.Short)
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

func TestRecoverCommandFlags(t *testing.T) {
	t.Run("recovery-kit-file flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagRecoveryKitPath)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagRecoveryKitPath)
			return
		}
		if flag.Name != flagRecoveryKitPath {
			t.Errorf("expected flag name '%s', got '%s'", flagRecoveryKitPath, flag.Name)
		}
	})

	t.Run("private-key-file flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyPath)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagPrivateKeyPath)
			return
		}
		if flag.Name != flagPrivateKeyPath {
			t.Errorf("expected flag name '%s', got '%s'", flagPrivateKeyPath, flag.Name)
		}
	})

	t.Run("quorum-id flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagQuorumID)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagQuorumID)
			return
		}
		if flag.Name != flagQuorumID {
			t.Errorf("expected flag name '%s', got '%s'", flagQuorumID, flag.Name)
		}
	})

	t.Run("key-id flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagKeyID)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagKeyID)
			return
		}
		if flag.Name != flagKeyID {
			t.Errorf("expected flag name '%s', got '%s'", flagKeyID, flag.Name)
		}
	})

	t.Run("key-type flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagKeyType)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagKeyType)
			return
		}
		if flag.Name != flagKeyType {
			t.Errorf("expected flag name '%s', got '%s'", flagKeyType, flag.Name)
		}
	})

	t.Run("output-file flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagOutputFile)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagOutputFile)
			return
		}
		if flag.Name != flagOutputFile {
			t.Errorf("expected flag name '%s', got '%s'", flagOutputFile, flag.Name)
		}
	})

	t.Run("encrypt-output flag exists", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagEncryptOutput)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptOutput)
			return
		}
		if flag.Name != flagEncryptOutput {
			t.Errorf("expected flag name '%s', got '%s'", flagEncryptOutput, flag.Name)
		}
	})
}

func TestRecoverCommandFlagDefaults(t *testing.T) {
	t.Run("encrypt-output flag defaults to true", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagEncryptOutput)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagEncryptOutput)
			return
		}
		if flag.DefValue != "true" {
			t.Errorf("expected encrypt-output default to be 'true', got '%s'", flag.DefValue)
		}
	})

	t.Run("recovery-kit-file flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagRecoveryKitPath)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagRecoveryKitPath)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected recovery-kit-file default to be empty, got '%s'", flag.DefValue)
		}
	})

	t.Run("private-key-file flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagPrivateKeyPath)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagPrivateKeyPath)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected private-key-file default to be empty, got '%s'", flag.DefValue)
		}
	})

	t.Run("quorum-id flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagQuorumID)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagQuorumID)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected quorum-id default to be empty, got '%s'", flag.DefValue)
		}
	})

	t.Run("key-id flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagKeyID)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagKeyID)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected key-id default to be empty, got '%s'", flag.DefValue)
		}
	})

	t.Run("key-type flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagKeyType)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagKeyType)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected key-type default to be empty, got '%s'", flag.DefValue)
		}
	})

	t.Run("output-file flag defaults to empty", func(t *testing.T) {
		flag := Cmd.Flags().Lookup(flagOutputFile)
		if flag == nil {
			t.Errorf("expected flag '%s' to exist", flagOutputFile)
			return
		}
		if flag.DefValue != "" {
			t.Errorf("expected output-file default to be empty, got '%s'", flag.DefValue)
		}
	})
}

func TestFlagConstants(t *testing.T) {
	t.Run("flagOutputFile constant is correct", func(t *testing.T) {
		if flagOutputFile != "output-file" {
			t.Errorf("expected constant to be 'output-file', got '%s'", flagOutputFile)
		}
	})

	t.Run("flagEncryptOutput constant is correct", func(t *testing.T) {
		if flagEncryptOutput != "encrypt-output" {
			t.Errorf("expected constant to be 'encrypt-output', got '%s'", flagEncryptOutput)
		}
	})

	t.Run("flagRecoveryKitPath constant is correct", func(t *testing.T) {
		if flagRecoveryKitPath != "recovery-kit-file" {
			t.Errorf("expected constant to be 'recovery-kit-file', got '%s'", flagRecoveryKitPath)
		}
	})

	t.Run("flagPrivateKeyPath constant is correct", func(t *testing.T) {
		if flagPrivateKeyPath != "private-key-file" {
			t.Errorf("expected constant to be 'private-key-file', got '%s'", flagPrivateKeyPath)
		}
	})

	t.Run("flagQuorumID constant is correct", func(t *testing.T) {
		if flagQuorumID != "quorum-id" {
			t.Errorf("expected constant to be 'quorum-id', got '%s'", flagQuorumID)
		}
	})

	t.Run("flagKeyID constant is correct", func(t *testing.T) {
		if flagKeyID != "key-id" {
			t.Errorf("expected constant to be 'key-id', got '%s'", flagKeyID)
		}
	})

	t.Run("flagKeyType constant is correct", func(t *testing.T) {
		if flagKeyType != "key-type" {
			t.Errorf("expected constant to be 'key-type', got '%s'", flagKeyType)
		}
	})
}
