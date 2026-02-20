// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package generate

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	flagPrivateKeyFile    = "private-key-file"
	flagPublicKeyFile     = "public-key-file"
	flagEncryptPrivateKey = "encrypt-private-key"
	flagFormat            = "format"
	minPasswordLength     = 8

	// Output format options
	formatDER = "der" // Binary DER (industry standard)
	formatHex = "hex" // Hex-encoded DER (legacy)
)

var Cmd = &cobra.Command{
	Use:   "generate-recovery-keypair",
	Short: "Generate a recovery keypair",
	Long: `Generate an RSA-4096 key pair for wallet backup and recovery.

This command creates a new RSA-4096 key pair used in the MPC recovery process:
- The PUBLIC key is uploaded to Palisade for encrypting wallet backups
- The PRIVATE key is kept secure by you for recovering wallet keys

The public key is output in PKIX DER format. By default, the output is binary DER
(industry standard). Use --format=hex for hex-encoded output (legacy format).
The public key should be uploaded through the Palisade Customer Portal or API.
The private key can optionally be encrypted with a password for additional security.

Output Formats:
  --format=der  Binary DER format (default, industry standard, ~550 bytes)
  --format=hex  Hex-encoded DER format (legacy, ~1100 characters)

Usage Flow:
  1. Generate the keypair (optionally with password encryption)
  2. Upload the public key to Palisade
  3. Store the private key securely
  4. Use the private key with the 'recover' command to recover wallet keys

Examples:
  # Generate a key pair with binary DER output (default)
  recovery generate-recovery-keypair \
    --private-key-file=private.der \
    --public-key-file=public.der

  # Generate with hex-encoded output (legacy format)
  recovery generate-recovery-keypair \
    --private-key-file=private.der \
    --public-key-file=public.hex \
    --format=hex

  # Generate with password-encrypted private key
  recovery generate-recovery-keypair \
    --private-key-file=private.der \
    --public-key-file=public.der \
    --encrypt-private-key

  # Generate with custom output directory
  recovery generate-recovery-keypair \
    --private-key-file=./keys/private.der \
    --public-key-file=./keys/public.der

Security Notes:
  - Store the private key securely (e.g., hardware security module, secure vault)
  - Never share or upload the private key
  - Back up the private key to a secure location
  - If using --encrypt-private-key, use a strong password (minimum 8 characters)
  - The private key file is created with restricted permissions (0400)
  - Consider using a password manager or HSM for password storage`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_ = cmd.Context() // Context available for cancellation support
		// validate inputs
		privateKeyFilePath, err := cmd.Flags().GetString(flagPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return fmt.Errorf("failed to retrieve private key file path: %w", err)
		}

		publicKeyFilePath, err := cmd.Flags().GetString(flagPublicKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return fmt.Errorf("failed to retrieve public key file path: %w", err)
		}

		// Validate file paths
		if err := utils.ValidateFilePath(privateKeyFilePath); err != nil {
			cmd.PrintErrln("Invalid private key file path:", err)
			return err
		}

		if err := utils.ValidateFilePath(publicKeyFilePath); err != nil {
			cmd.PrintErrln("Invalid public key file path:", err)
			return err
		}

		encryptPrivateKey, err := cmd.Flags().GetBool(flagEncryptPrivateKey)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypt private key flag:", err)
			return fmt.Errorf("failed to retrieve encrypt private key flag: %w", err)
		}

		outputFormat, err := cmd.Flags().GetString(flagFormat)
		if err != nil {
			cmd.PrintErrln("Error retrieving format flag:", err)
			return fmt.Errorf("failed to retrieve format flag: %w", err)
		}

		// Validate format
		if outputFormat != formatDER && outputFormat != formatHex {
			cmd.PrintErrf("Invalid format %q: must be 'der' or 'hex'\n", outputFormat)
			return fmt.Errorf("invalid format %q: must be 'der' or 'hex'", outputFormat)
		}

		// Collect password BEFORE key generation to fail fast and minimize sensitive data lifetime
		var passwordBytes []byte
		if encryptPrivateKey {
			fmt.Fprint(cmd.OutOrStdout(), "Enter password to encrypt private key: ")
			passwordBytes, err = term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("\nError reading password:", err)
				return fmt.Errorf("failed to read password: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout())

			if len(passwordBytes) < minPasswordLength {
				utils.ClearSensitiveBytes(passwordBytes)
				cmd.PrintErrf("Password must be at least %d characters\n", minPasswordLength)
				return fmt.Errorf("password must be at least %d characters", minPasswordLength)
			}

			fmt.Fprint(cmd.OutOrStdout(), "Confirm password: ")
			confirmPasswordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				utils.ClearSensitiveBytes(passwordBytes)
				cmd.PrintErrln("\nError reading password confirmation:", err)
				return fmt.Errorf("failed to read password confirmation: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout())

			if !bytes.Equal(passwordBytes, confirmPasswordBytes) {
				utils.ClearSensitiveBytes(passwordBytes)
				utils.ClearSensitiveBytes(confirmPasswordBytes)
				cmd.PrintErrln("Passwords do not match")
				return fmt.Errorf("passwords do not match")
			}
			utils.ClearSensitiveBytes(confirmPasswordBytes)
		}

		// generate the keypair
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			utils.ClearSensitiveBytes(passwordBytes)
			cmd.PrintErrln("Error generating RSA keypair:", err)
			return fmt.Errorf("failed to generate rsa keypair: %w", err)
		}

		// Convert private key to DER format
		privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
		defer utils.ClearSensitiveBytes(privateKeyDER)

		// Convert to hex string
		privateKeyHex := hex.EncodeToString(privateKeyDER)

		// Extract public key and convert to DER format
		publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			utils.ClearSensitiveBytes(passwordBytes)
			cmd.PrintErrln("Error encoding public key:", err)
			return fmt.Errorf("failed to encode public key: %w", err)
		}
		// Convert to hex string
		publicKeyHex := hex.EncodeToString(publicKeyDER)

		// write private key to private key file
		privateKeyFile, err := os.OpenFile(privateKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
		if err != nil {
			utils.ClearSensitiveBytes(passwordBytes)
			cmd.PrintErrln("Error creating private key file:", err)
			return fmt.Errorf("failed to create private key file: %w", err)
		}
		defer func() {
			if err := privateKeyFile.Close(); err != nil {
				cmd.PrintErrln("Error closing private key file:", err)
			}
		}()

		if encryptPrivateKey {
			encryptedBytes, err := utils.EncryptWithHeader(passwordBytes, []byte(privateKeyHex))
			// passwordBytes is cleared by EncryptWithHeader
			if err != nil {
				cmd.PrintErrln("Error encrypting private key:", err)
				return fmt.Errorf("failed to encrypt private key: %w", err)
			}

			if _, err := privateKeyFile.Write(encryptedBytes); err != nil {
				cmd.PrintErrln("Error writing encrypted private key to file:", err)
				return fmt.Errorf("failed to write encrypted private key to file: %w", err)
			}
		} else {
			if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
				cmd.PrintErrln("Error writing private key to file:", err)
				return fmt.Errorf("failed to write private key to file: %w", err)
			}
		}

		// write public key to public key file
		publicKeyFile, err := os.OpenFile(publicKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o400)
		if err != nil {
			cmd.PrintErrln("Error creating public key file:", err)
			return fmt.Errorf("failed to create public key file: %w", err)
		}
		defer func() {
			if err := publicKeyFile.Close(); err != nil {
				cmd.PrintErrln("Error closing public key file:", err)
			}
		}()

		// Write public key in the requested format
		switch outputFormat {
		case formatDER:
			// Binary DER format (industry standard)
			if _, err := publicKeyFile.Write(publicKeyDER); err != nil {
				cmd.PrintErrln("Error writing public key to file:", err)
				return fmt.Errorf("failed to write public key to file: %w", err)
			}
		case formatHex:
			// Hex-encoded DER format (legacy)
			if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
				cmd.PrintErrln("Error writing public key to file:", err)
				return fmt.Errorf("failed to write public key to file: %w", err)
			}
		}

		if encryptPrivateKey {
			cmd.Printf("Recovery keypair generated successfully (public key format: %s). Private key is encrypted.\n", outputFormat)
		} else {
			cmd.Printf("Recovery keypair generated successfully (public key format: %s).\n", outputFormat)
		}
		return nil
	},
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "File path to save the private key. Must not exist.")
	Cmd.Flags().String(flagPublicKeyFile, "", "File path to save the public key. Must not exist.")
	Cmd.Flags().Bool(flagEncryptPrivateKey, false, "Encrypt the private key with a password")
	Cmd.Flags().String(flagFormat, formatDER, "Output format for public key: 'der' (binary, default) or 'hex' (hex-encoded)")
	Cmd.MarkFlagsRequiredTogether(flagPrivateKeyFile, flagPublicKeyFile)
}
