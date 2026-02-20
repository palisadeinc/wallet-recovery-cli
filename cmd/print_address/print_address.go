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

const flagPrivateKeyFile = "private-key-file"

var Cmd = &cobra.Command{
	Use:   "print-address",
	Short: "Print blockchain address associated with recovered private key",
	Long: `Derive and print the blockchain address from a recovered private key.

This command reads a private key file (encrypted or plain text) and derives the
corresponding blockchain address. It supports multiple key types and chains:
  - SECP256K1 keys: Derives EVM-compatible Ethereum addresses
  - ED25519 keys: Derives Solana addresses

The command automatically detects:
  - Whether the file is encrypted (by checking for the PKE1 header)
  - The key type from the private key content

Supported Chains:
  - Ethereum and EVM-compatible chains (SECP256K1)
  - Solana (ED25519)

Examples:
  # Print address from plain-text private key
  recovery print-address --private-key-file=recovered_key.der

  # Print address from encrypted private key (auto-detected)
  recovery print-address --private-key-file=recovered_key.enc
  # You will be prompted for the password

  # Print address from a recovery keypair
  recovery print-address --private-key-file=private.der

  # Verify address matches your wallet
  recovery print-address --private-key-file=recovered_key.der
  # Compare output with your wallet's address to verify recovery was successful

Workflow:
  1. Run the command with your private key file
  2. If the file is encrypted (auto-detected), you will be prompted for the password
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

		// Read the file first to check for encryption header
		fileBytes, err := utils.OpenReadOnlyFile(privateKeyFilePath)
		if err != nil {
			cmd.PrintErrln("Error reading private key file:", err)
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		defer utils.ClearSensitiveBytes(fileBytes)

		var contentBytes []byte
		defer func() {
			utils.ClearSensitiveBytes(contentBytes)
		}()

		// Auto-detect encryption by checking for PKE1 header or attempting decryption
		// We support both headerless (legacy) and header-based (PKE1) encrypted files
		if utils.HasEncryptionHeader(fileBytes) {
			cmd.Println("Encrypted private key detected (PKE1 header).")
			cmd.Print("Enter password to decrypt private key: ")
			passwordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("\nError reading password:", err)
				return fmt.Errorf("failed to read password: %w", err)
			}
			cmd.Println()

			contentBytes, err = utils.DecryptWithHeader(passwordBytes, fileBytes)
			// passwordBytes is cleared by DecryptWithHeader
			if err != nil {
				cmd.PrintErrln("Error decrypting private key: incorrect password or corrupted file")
				return fmt.Errorf("failed to decrypt private key file: %w", err)
			}
		} else if utils.LooksLikeEncryptedData(fileBytes) {
			// Legacy headerless encrypted file - try to decrypt
			cmd.Println("Encrypted private key detected (legacy format).")
			cmd.Print("Enter password to decrypt private key: ")
			passwordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("\nError reading password:", err)
				return fmt.Errorf("failed to read password: %w", err)
			}
			cmd.Println()

			contentBytes, err = utils.DecryptData(passwordBytes, fileBytes)
			// passwordBytes is cleared by DecryptData
			if err != nil {
				cmd.PrintErrln("Error decrypting private key: incorrect password or corrupted file")
				return fmt.Errorf("failed to decrypt private key file: %w", err)
			}
		} else {
			// Not encrypted - use file bytes directly
			contentBytes = make([]byte, len(fileBytes))
			copy(contentBytes, fileBytes)
		}

		// Try to derive Ethereum address first (SECP256K1 keys)
		address, err := utils.GetEthereumAddressFromPrivateKeyBytes(contentBytes)
		if err == nil {
			cmd.Println("EVM-compatible address:", address)
			return nil
		}

		// If Ethereum derivation fails, try Solana (ED25519 keys)
		solanaAddress, solanaErr := utils.GetSolanaAddressFromPrivateKeyBytes(contentBytes)
		if solanaErr == nil {
			cmd.Println("Solana address:", solanaAddress)
			return nil
		}

		// Both failed - report the original Ethereum error as it's more common
		cmd.PrintErrln("Error deriving address from private key bytes:", err)
		return fmt.Errorf("failed to derive address from private key bytes (tried Ethereum and Solana): %w", err)
	},
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "Path to file containing private key (encrypted or plain). Must exist and be readable.")
	if err := Cmd.MarkFlagRequired(flagPrivateKeyFile); err != nil {
		Cmd.PrintErrln("Error marking private key file as required:", err)
		return
	}
}
