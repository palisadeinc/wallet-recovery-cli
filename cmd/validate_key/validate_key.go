// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package validate_key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagPrivateKeyFile = "private-key-file"

var Cmd = &cobra.Command{
	Use:   "validate-private-key",
	Short: "Validate password for an encrypted private key",
	Long: `Validate that a password can decrypt an encrypted RSA private key file.

This command tests whether a password can successfully decrypt an encrypted private
key file without modifying the original file. It's useful for:
  - Verifying you have the correct password before critical operations
  - Testing password recovery procedures
  - Validating key file integrity
  - Confirming a key is properly encrypted

The command performs the following checks:
  1. Reads the private key file
  2. Detects if the file is encrypted (checks for encryption header)
  3. If encrypted, prompts for the password and attempts decryption
  4. Validates the decrypted content is a valid RSA private key
  5. Reports success or failure without modifying the file

Examples:
  # Validate an encrypted recovery keypair
  recovery validate-private-key --private-key-file=private.der.enc
  # Output: "Validation successful: password is correct and private key is valid"

  # Validate an encrypted recovered key
  recovery validate-private-key --private-key-file=recovered_key.enc

  # Validate a plain-text key (no password needed)
  recovery validate-private-key --private-key-file=private.der
  # Output: "Private key file is not encrypted. No password validation needed."

  # Test password before recovery operation
  recovery validate-private-key --private-key-file=private.der.enc
  # If validation succeeds, you can proceed with the 'recover' command

Workflow:
  1. Run the command with your encrypted key file
  2. Enter the password when prompted
  3. The command validates the password and key integrity
  4. If successful, you can use the key with other commands
  5. If failed, verify the password and try again

Security Notes:
  - The original file is never modified
  - The password is read securely from the terminal
  - Decrypted content is cleared from memory after validation
  - Supports both PKCS1 and PKCS8 RSA private key formats
  - Use this command to verify key integrity periodically
  - If validation fails, check that you have the correct password`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_ = cmd.Context() // Context available for cancellation support
		privateKeyFilePath, err := cmd.Flags().GetString(flagPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return fmt.Errorf("failed to retrieve private key file path: %w", err)
		}

		// Validate file path
		if err := utils.ValidateFilePath(privateKeyFilePath); err != nil {
			cmd.PrintErrln("Invalid private key file path:", err)
			return fmt.Errorf("invalid private key file path: %w", err)
		}

		// Read the file
		fileBytes, err := utils.OpenReadOnlyFile(privateKeyFilePath)
		if err != nil {
			cmd.PrintErrln("Error reading private key file:", err)
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		defer utils.ClearSensitiveBytes(fileBytes)

		// Check if the file is encrypted (has PKE1 header)
		if !utils.HasEncryptionHeader(fileBytes) {
			// Not encrypted - check if it's a valid plain hex private key
			if isValidPlainPrivateKey(fileBytes) {
				cmd.Println("Private key file is not encrypted. No password validation needed.")
				return nil
			}
			cmd.PrintErrln("Not a valid private key file: file is neither encrypted nor a valid hex-encoded RSA private key")
			return fmt.Errorf("not a valid private key file: file is neither encrypted nor a valid hex-encoded RSA private key")
		}

		// File is encrypted - prompt for password
		cmd.Print("Enter password to validate: ")
		passwordBytes, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			cmd.PrintErrln("\nError reading password:", err)
			return fmt.Errorf("failed to read password: %w", err)
		}
		cmd.Println()

		// Attempt to decrypt
		decryptedBytes, err := utils.DecryptWithHeader(passwordBytes, fileBytes)
		if err != nil {
			cmd.PrintErrln("Validation failed: incorrect password or corrupted file")
			return fmt.Errorf("failed to decrypt file: %w", err)
		}
		defer utils.ClearSensitiveBytes(decryptedBytes)

		// Validate the decrypted content is a valid RSA private key
		if !isValidPlainPrivateKey(decryptedBytes) {
			cmd.PrintErrln("Validation failed: decrypted content is not a valid RSA private key")
			return fmt.Errorf("validation failed: decrypted content is not a valid RSA private key")
		}

		cmd.Println("Validation successful: password is correct and private key is valid")
		return nil
	},
}

// isValidPlainPrivateKey checks if the bytes represent a valid hex-encoded RSA private key
func isValidPlainPrivateKey(data []byte) bool {
	// Convert to string and strip whitespace
	hexStr := string(data)
	hexStr = strings.ReplaceAll(hexStr, "\n", "")
	hexStr = strings.ReplaceAll(hexStr, "\r", "")
	hexStr = strings.ReplaceAll(hexStr, " ", "")
	hexStr = strings.ReplaceAll(hexStr, "\t", "")

	// Try to decode hex
	derBytes, err := hex.DecodeString(hexStr)
	if err != nil {
		return false
	}
	defer utils.ClearSensitiveBytes(derBytes)

	// Try to parse as PKCS8 first, then PKCS1
	privateKey, err := x509.ParsePKCS8PrivateKey(derBytes)
	if err != nil {
		privateKey, err = x509.ParsePKCS1PrivateKey(derBytes)
		if err != nil {
			return false
		}
	}

	// Verify it's an RSA key
	_, ok := privateKey.(*rsa.PrivateKey)
	return ok
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "Path to the private key file to validate")
	if err := Cmd.MarkFlagRequired(flagPrivateKeyFile); err != nil {
		Cmd.PrintErrln("Error marking private key file as required:", err)
		return
	}
}
