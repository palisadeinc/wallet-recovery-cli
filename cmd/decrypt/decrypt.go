// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package decrypt

import (
	"fmt"
	"syscall"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	flagEncryptedPrivateKeyFile = "encrypted-private-key-file"
	flagDecryptedOutputFile     = "decrypted-output-file"
)

var Cmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an encrypted recovery private key file",
	Long: `Decrypt an encrypted private key file generated using the recover command.

This command decrypts a private key file that was encrypted during the recovery process.
It reads the encrypted file, prompts for the password, and writes the decrypted key to
a new file. The original encrypted file is not modified.

Use Cases:
  - Decrypt a recovered private key saved with --encrypt-output=true
  - Decrypt a recovery keypair generated with --encrypt-private-key
  - Temporarily decrypt a key for use in other tools

Examples:
  # Decrypt a recovered private key
  recovery decrypt \
    --encrypted-private-key-file=recovered_key.enc \
    --decrypted-output-file=recovered_key.der

  # Decrypt a recovery keypair
  recovery decrypt \
    --encrypted-private-key-file=private.der.enc \
    --decrypted-output-file=private.der

  # Decrypt and use with another tool
  recovery decrypt \
    --encrypted-private-key-file=wallet_key.enc \
    --decrypted-output-file=/tmp/wallet_key.der
  # Then use /tmp/wallet_key.der with your wallet software
  # Remember to securely delete /tmp/wallet_key.der when done

Workflow:
  1. Run the decrypt command with the encrypted file path
  2. Enter the password when prompted
  3. The decrypted key is written to the output file
  4. Use the decrypted key as needed
  5. Securely delete the decrypted file when no longer needed

Security Notes:
  - The decrypted output file is created with restricted permissions (0400)
  - Only decrypt keys when you need to use them
  - Securely delete decrypted files after use (consider using 'shred' or 'srm')
  - Keep encrypted files as your primary storage method
  - The original encrypted file is never modified
  - Ensure the output file path does not already exist`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_ = cmd.Context() // Context available for cancellation support
		// validate inputs
		encryptedPrivateKeyFilePath, err := cmd.Flags().GetString(flagEncryptedPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypted private key file path:", err)
			return fmt.Errorf("failed to retrieve encrypted private key file path: %w", err)
		}

		decryptedOutputFilePath, err := cmd.Flags().GetString(flagDecryptedOutputFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving decrypted output file path:", err)
			return fmt.Errorf("failed to retrieve decrypted output file path: %w", err)
		}

		// Validate file paths
		if err := utils.ValidateFilePath(encryptedPrivateKeyFilePath); err != nil {
			cmd.PrintErrln("Invalid encrypted private key file path:", err)
			return err
		}

		if err := utils.ValidateFilePath(decryptedOutputFilePath); err != nil {
			cmd.PrintErrln("Invalid decrypted output file path:", err)
			return err
		}

		if decryptedOutputFilePath == encryptedPrivateKeyFilePath {
			cmd.PrintErrln("Decrypted output file path cannot be the same as the encrypted private key file path")
			return fmt.Errorf("decrypted output file path cannot be the same as the encrypted private key file path")
		}

		cmd.Print("Enter encryption password: ")
		passwordBytes, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			cmd.PrintErrln("Error reading password:", err)
			return fmt.Errorf("failed to read password: %w", err)
		}
		cmd.Println()

		encryptedPrivateKeyFileBytes, err := utils.OpenReadOnlyFile(encryptedPrivateKeyFilePath)
		if err != nil {
			cmd.PrintErrln("Error opening encrypted private key file:", err)
			return fmt.Errorf("failed to open encrypted private key file: %w", err)
		}

		// Support both header-based (PKE1) and headerless (legacy) encrypted files
		var contentBytes []byte
		if utils.HasEncryptionHeader(encryptedPrivateKeyFileBytes) {
			contentBytes, err = utils.DecryptWithHeader(passwordBytes, encryptedPrivateKeyFileBytes)
		} else {
			contentBytes, err = utils.DecryptData(passwordBytes, encryptedPrivateKeyFileBytes)
		}
		if err != nil {
			cmd.PrintErrln("Error decrypting private key file: incorrect password or corrupted file")
			return fmt.Errorf("failed to decrypt private key file: %w", err)
		}

		if err := utils.WriteToFile(decryptedOutputFilePath, contentBytes); err != nil {
			cmd.PrintErrln("Error writing decrypted private key file:", err)
			return fmt.Errorf("failed to write decrypted private key file: %w", err)
		}

		cmd.Println("Decrypted private key file saved successfully")
		return nil
	},
}

func init() {
	Cmd.Flags().String(flagEncryptedPrivateKeyFile, "", "Path to file containing encrypted private key. Must exist and be readable.")
	Cmd.Flags().String(flagDecryptedOutputFile, "", "Path to file containing decrypted private key. Must not exist.")
	if err := Cmd.MarkFlagRequired(flagEncryptedPrivateKeyFile); err != nil {
		Cmd.PrintErrln("Error marking encrypted private key file as required:", err)
		return
	}
	if err := Cmd.MarkFlagRequired(flagDecryptedOutputFile); err != nil {
		Cmd.PrintErrln("Error marking decrypted output file as required:", err)
		return
	}
	Cmd.MarkFlagsRequiredTogether(flagEncryptedPrivateKeyFile, flagDecryptedOutputFile)
}
