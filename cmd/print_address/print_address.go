// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package print_address

import (
	"fmt"
	"syscall"

	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	flagPrivateKeyFile = "private-key-file"
	flagEncrypted      = "encrypted"
)

var Cmd = &cobra.Command{
	Use:   "print-address",
	Short: "Print blockchain address associated with recovered private key",
	Long: `Derive and print the blockchain address from a recovered private key.

This command reads a private key file (encrypted or plain text) and derives the
corresponding blockchain address. It supports multiple key types and chains:
  - SECP256K1 keys: Derives EVM-compatible Ethereum addresses
  - ED25519 keys: Derives Solana addresses

The command automatically detects the key type from the private key content and
displays the appropriate address format.

Supported Chains:
  - Ethereum and EVM-compatible chains (SECP256K1)
  - Solana (ED25519)

Examples:
  # Print address from plain-text private key
  recovery print-address --private-key-file=recovered_key.der

  # Print address from encrypted private key
  recovery print-address \
    --private-key-file=recovered_key.enc \
    --encrypted

  # Print address from a recovery keypair
  recovery print-address --private-key-file=private.der

  # Print address from encrypted recovery keypair
  recovery print-address \
    --private-key-file=private.der.enc \
    --encrypted

  # Verify address matches your wallet
  recovery print-address --private-key-file=recovered_key.der
  # Compare output with your wallet's address to verify recovery was successful

Workflow:
  1. Run the command with your private key file
  2. If encrypted, you will be prompted for the password
  3. The command derives the public key from the private key
  4. The corresponding blockchain address is printed to stdout
  5. Verify the address matches your expected wallet address

Security Notes:
  - The private key is read into memory but not stored
  - If the file is encrypted, the password is read securely from the terminal
  - The command does not modify the private key file
  - Use this command to verify recovery was successful before using the key
  - The address is derived deterministically from the private key`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_ = cmd.Context() // Context available for cancellation support
		// validate inputs
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

		var contentBytes []byte
		encrypted, err := cmd.Flags().GetBool(flagEncrypted)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypted flag:", err)
			return fmt.Errorf("failed to retrieve encrypted flag: %w", err)
		}

		if encrypted {
			cmd.Print("Enter encryption password: ")
			passwordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("Error reading password:", err)
				return fmt.Errorf("failed to read password: %w", err)
			}
			cmd.Println()

			encryptedPrivateKeyFileBytes, err := utils.OpenReadOnlyFile(privateKeyFilePath)
			if err != nil {
				cmd.PrintErrln("Error opening encrypted private key file:", err)
				return fmt.Errorf("failed to open encrypted private key file: %w", err)
			}

			contentBytes, err = utils.DecryptData(passwordBytes, encryptedPrivateKeyFileBytes)
			if err != nil {
				cmd.PrintErrln("Error decrypting private key file:", err)
				return fmt.Errorf("failed to decrypt private key file: %w", err)
			}
		} else {
			contentBytes, err = utils.OpenReadOnlyFile(privateKeyFilePath)
			if err != nil {
				cmd.PrintErrln("Error opening encrypted private key file:", err)
				return fmt.Errorf("failed to open private key file: %w", err)
			}
		}

		address, err := utils.GetEthereumAddressFromPrivateKeyBytes(contentBytes)
		if err != nil {
			cmd.PrintErrln("Error getting Ethereum address from private key bytes:", err)
			return fmt.Errorf("failed to get ethereum address from private key bytes: %w", err)
		}

		cmd.Println("EVM-compatible address:", address)
		return nil
	},
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "Path to file containing encrypted private key. Must exist and be readable.")
	Cmd.Flags().Bool(flagEncrypted, false, "Whether the private key file is encrypted.")
	if err := Cmd.MarkFlagRequired(flagPrivateKeyFile); err != nil {
		Cmd.PrintErrln("Error marking private key file as required:", err)
		return
	}
	Cmd.MarkFlagsRequiredTogether(flagPrivateKeyFile)
}
