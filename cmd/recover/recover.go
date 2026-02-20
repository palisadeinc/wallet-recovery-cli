// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package recover //nolint:predeclared // Package name matches command name; imported with alias to avoid shadowing

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/palisadeinc/wallet-recovery-cli/models"
	"github.com/palisadeinc/wallet-recovery-cli/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const (
	flagOutputFile      = "output-file"
	flagEncryptOutput   = "encrypt-output"
	flagRecoveryKitPath = "recovery-kit-file"
	flagPrivateKeyPath  = "private-key-file"
	flagQuorumID        = "quorum-id"
	flagKeyID           = "key-id"
	flagKeyType         = "key-type"
)

var Cmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover a private key from recovery data",
	Long: `Recover a private key from recovery data using cryptographic primitives.

This command performs the core MPC recovery operation. It takes a recovery kit file
(downloaded from Palisade) and your RSA private key to recover the original wallet
private key. The command supports both SECP256K1 (Ethereum/EVM) and ED25519 (Solana)
key types.

Recovery Process:
  1. Reads and parses the recovery kit file and RSA private key
  2. Validates that the public key derived from the RSA private key matches the
     public key stored in the recovery data
  3. Determines the key type (from flag or recovery kit metadata)
  4. Validates the integrity of the recovery data using the appropriate algorithm
  5. Recovers the private key using the recovery data and RSA private key
  6. Displays the corresponding blockchain address
  7. Optionally saves the recovered private key to a file (encrypted or plain)

Supported Key Types:
  - SECP256K1: For Ethereum and EVM-compatible chains (displays Ethereum and XRP addresses)
  - ED25519: For Solana (displays Solana address)

Examples:
  # Recover a SECP256K1 key and display the address
  recovery recover \
    --recovery-kit-file=recovery_kit.json \
    --private-key-file=private.der \
    --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
    --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8

  # Recover an ED25519 key for Solana
  recovery recover \
    --recovery-kit-file=recovery_kit.json \
    --private-key-file=private.der \
    --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
    --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
    --key-type=ED25519

  # Recover and save to encrypted file
  recovery recover \
    --recovery-kit-file=recovery_kit.json \
    --private-key-file=private.der \
    --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
    --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
    --output-file=recovered_key.enc \
    --encrypt-output=true

  # Recover and save to plain text file (not recommended)
  recovery recover \
    --recovery-kit-file=recovery_kit.json \
    --private-key-file=private.der \
    --quorum-id=550e8400-e29b-41d4-a716-446655440000 \
    --key-id=6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
    --output-file=recovered_key.der \
    --encrypt-output=false

Security Notes:
  - The recovered private key is sensitive and should be handled with care
  - By default, output files are encrypted (--encrypt-output=true)
  - If your RSA private key is encrypted, you will be prompted for the password
  - The command validates recovery data integrity before attempting recovery
  - Consider using the 'decrypt' command to decrypt saved keys only when needed`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		_ = cmd.Context() // Context available for cancellation support
		recoveryKitPath, err := cmd.Flags().GetString(flagRecoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving file path:", err)
			return fmt.Errorf("failed to retrieve recovery kit path: %w", err)
		}

		privateKeyPath, err := cmd.Flags().GetString(flagPrivateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key:", err)
			return fmt.Errorf("failed to retrieve private key path: %w", err)
		}

		// Validate file paths
		if err := utils.ValidateFilePath(recoveryKitPath); err != nil {
			cmd.PrintErrln("Invalid recovery kit file path:", err)
			return err
		}

		if err := utils.ValidateFilePath(privateKeyPath); err != nil {
			cmd.PrintErrln("Invalid private key file path:", err)
			return err
		}

		recoveryKitBase64Bytes, err := utils.OpenReadOnlyFile(recoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error opening file:", err)
			return fmt.Errorf("failed to open recovery kit file: %w", err)
		}

		privateKeyBytes, err := utils.OpenReadOnlyFile(privateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error opening private key file:", err)
			return fmt.Errorf("failed to open private key file: %w", err)
		}

		defer utils.ClearSensitiveBytes(privateKeyBytes)

		var privateKeyHex string

		// Auto-detect encrypted private key by checking for magic header
		if utils.HasEncryptionHeader(privateKeyBytes) {
			cmd.Println("Encrypted private key detected.")
			cmd.Print("Enter password to decrypt private key: ")
			passwordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("\nError reading password:", err)
				return fmt.Errorf("failed to read password: %w", err)
			}
			cmd.Println()

			decryptedBytes, err := utils.DecryptWithHeader(passwordBytes, privateKeyBytes)
			// passwordBytes is cleared by DecryptWithHeader
			if err != nil {
				cmd.PrintErrln("Error decrypting private key: incorrect password or corrupted file")
				return fmt.Errorf("failed to decrypt private key: %w", err)
			}

			// Clear original encrypted bytes now that we have decrypted
			utils.ClearSensitiveBytes(privateKeyBytes)

			privateKeyHex = string(decryptedBytes)
			defer utils.ClearSensitiveBytes(decryptedBytes)
		} else {
			privateKeyHex = string(privateKeyBytes)
			// Remove all whitespace characters
			privateKeyHex = strings.ReplaceAll(privateKeyHex, "\n", "")
			privateKeyHex = strings.ReplaceAll(privateKeyHex, "\r", "")
			privateKeyHex = strings.ReplaceAll(privateKeyHex, " ", "")
			privateKeyHex = strings.ReplaceAll(privateKeyHex, "\t", "")
		}

		privateKeyDerBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			cmd.PrintErrln("Error decoding private key:", err)
			return fmt.Errorf("failed to decode private key: %w", err)
		}

		defer utils.ClearSensitiveBytes(privateKeyDerBytes)

		ersPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDerBytes)
		if err != nil {
			// try using pkcs1
			ersPrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDerBytes)
			if err != nil {
				cmd.PrintErrln("Error parsing private key:", err)
				return fmt.Errorf("failed to parse private key: %w", err)
			}
		}

		ersRSAPrivateKey, ok := ersPrivateKey.(*rsa.PrivateKey)
		if !ok {
			cmd.PrintErrln("Invalid private key, expected PKCS8 Private Key")
			return fmt.Errorf("invalid private key, expected pkcs8 private key")
		}

		recoveryKitBytes, err := base64.StdEncoding.DecodeString(string(recoveryKitBase64Bytes))
		if err != nil {
			cmd.PrintErrln("Error decoding base64 recoveryKit:", err)
			return fmt.Errorf("failed to decode base64 recovery kit: %w", err)
		}

		defer utils.ClearSensitiveBytes(recoveryKitBytes)

		var recoveryKit models.RecoveryDataObject
		if err := json.Unmarshal(recoveryKitBytes, &recoveryKit); err != nil {
			cmd.PrintErrln("Error unmarshalling recovery kit:", err)
			return fmt.Errorf("failed to unmarshal recovery kit: %w", err)
		}

		// check if recoveryKit.RecoveryPublicKeyHex belongs to the private key
		// Generate the RSA public key from the private key
		ersPublicKey := ersRSAPrivateKey.Public().(*rsa.PublicKey)
		ersPublicKeyBytes, err := x509.MarshalPKIXPublicKey(ersPublicKey)
		if err != nil {
			cmd.PrintErrln("Error marshalling public key:", err)
			return fmt.Errorf("failed to marshal public key: %w", err)
		}

		ersPublicKeyHex := hex.EncodeToString(ersPublicKeyBytes)
		if recoveryKit.RecoveryPublicKeyHex != ersPublicKeyHex {
			cmd.PrintErrln("Recovery public key does not match the private key.")
			return fmt.Errorf("recovery public key does not match the private key")
		}
		cmd.Println("Recovery public key matches the private key.")

		recoveryDataBytes, err := base64.StdEncoding.DecodeString(recoveryKit.PartialRecoveryDataBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding recovery data:", err)
			return fmt.Errorf("failed to decode recovery data: %w", err)
		}

		defer utils.ClearSensitiveBytes(recoveryDataBytes)

		quorumIDStr, err := cmd.Flags().GetString(flagQuorumID)
		if err != nil {
			cmd.PrintErrln("Error retrieving quorum ID:", err)
			return fmt.Errorf("failed to retrieve quorum id: %w", err)
		}

		// Validate quorum ID format
		if err := utils.ValidateUUID(quorumIDStr, "quorum-id"); err != nil {
			cmd.PrintErrln(err)
			return err
		}

		quorumID, err := uuid.Parse(quorumIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing quorum ID:", err)
			return fmt.Errorf("failed to parse quorum id: %w", err)
		}

		keyIDStr, err := cmd.Flags().GetString(flagKeyID)
		if err != nil {
			cmd.PrintErrln("Error retrieving key ID:", err)
			return fmt.Errorf("failed to retrieve key id: %w", err)
		}

		// Validate key ID format
		if err := utils.ValidateUUID(keyIDStr, "key-id"); err != nil {
			cmd.PrintErrln(err)
			return err
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing key ID:", err)
			return fmt.Errorf("failed to parse key id: %w", err)
		}

		rootWalletKeyPkix, err := base64.StdEncoding.DecodeString(recoveryKit.WalletRootPublicKeyPkixBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding wallet root public key:", err)
			return fmt.Errorf("failed to decode wallet root public key: %w", err)
		}

		defer utils.ClearSensitiveBytes(rootWalletKeyPkix)

		// Check key type flag
		keyType, err := cmd.Flags().GetString(flagKeyType)
		if err != nil {
			cmd.PrintErrln("Error retrieving key type:", err)
			return fmt.Errorf("failed to retrieve key type: %w", err)
		}

		// Default to SECP256K1 if not specified (for backward compatibility)
		if keyType == "" {
			keyType = string(models.KeyAlgorithmSECP256K1)
		} else {
			// Validate key type format if explicitly provided
			if err := utils.ValidateKeyType(keyType); err != nil {
				cmd.PrintErrln(err)
				return err
			}
		}

		// Check if recovery kit specifies key algorithm
		if recoveryKit.KeyAlgorithm != "" {
			// If both are specified, they must match
			if keyType != string(recoveryKit.KeyAlgorithm) {
				cmd.PrintErrln(
					"Key type mismatch: flag specifies", keyType, "but recovery kit specifies",
					recoveryKit.KeyAlgorithm,
				)
				return fmt.Errorf("key type mismatch: flag specifies %s but recovery kit specifies %s", keyType, recoveryKit.KeyAlgorithm)
			}
			keyType = string(recoveryKit.KeyAlgorithm)
		}

		// Recover private key based on key type
		switch models.KeyAlgorithm(keyType) {
		case models.KeyAlgorithmSECP256K1:
			privateKeyBytes, err = utils.RecoverECDSAPrivateKey(
				recoveryDataBytes, rootWalletKeyPkix, quorumID, keyID, ersRSAPrivateKey, ersPublicKey,
			)
			if err != nil {
				cmd.PrintErrln("Error recovering SECP256K1 private key:", err)
				return fmt.Errorf("failed to recover secp256k1 private key: %w", err)
			}

			defer utils.ClearSensitiveBytes(privateKeyBytes)

			// Display both Ethereum and XRP addresses for SECP256K1 keys
			ethereumAddress, err := utils.GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting Ethereum address:", err)
				return fmt.Errorf("failed to get ethereum address: %w", err)
			}
			cmd.Printf("Ethereum address: %s\n", ethereumAddress)

			xrpAddress, err := utils.GetXRPAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting XRP address:", err)
				return fmt.Errorf("failed to get xrp address: %w", err)
			}
			cmd.Printf("XRP address: %s\n", xrpAddress)

		case models.KeyAlgorithmED25519:
			privateKeyBytes, err = utils.RecoverED25519PrivateKey(
				recoveryDataBytes, rootWalletKeyPkix, quorumID, keyID, ersRSAPrivateKey, ersPublicKey,
			)
			if err != nil {
				cmd.PrintErrln("Error recovering ED25519 private key:", err)
				return fmt.Errorf("failed to recover ed25519 private key: %w", err)
			}

			defer utils.ClearSensitiveBytes(privateKeyBytes)

			solanaAddress, err := utils.GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting Solana address:", err)
				return fmt.Errorf("failed to get solana address: %w", err)
			}

			cmd.Printf("Solana address: %s\n", solanaAddress)

		default:
			cmd.PrintErrln("Unsupported key type:", keyType)
			return fmt.Errorf("unsupported key type: %s", keyType)
		}

		fileOutput := cmd.Flags().Changed(flagOutputFile)
		if fileOutput {
			outputFilePath, err := cmd.Flags().GetString(flagOutputFile)
			if err != nil {
				cmd.PrintErrln("Error retrieving output file path:", err)
				return fmt.Errorf("failed to retrieve output file path: %w", err)
			}

			// Validate output file path
			if err := utils.ValidateFilePath(outputFilePath); err != nil {
				cmd.PrintErrln("Invalid output file path:", err)
				return fmt.Errorf("invalid output file path: %w", err)
			}

			cmd.Println("Writing private key to file...", outputFilePath)
			contentBytes := privateKeyBytes
			format := "plain"
			if encryptOutput := cmd.Flags().Changed(flagEncryptOutput); encryptOutput {
				format = "encrypted"
				encryptOutput, err = cmd.Flags().GetBool(flagEncryptOutput)
				if err != nil {
					cmd.PrintErrln("Error retrieving encrypt output flag:", err)
					return fmt.Errorf("failed to retrieve encrypt output flag: %w", err)
				}

				if encryptOutput {
					// Prompt for password
					cmd.Print("Enter password for encryption: ")
					passwordBytes, err := term.ReadPassword(syscall.Stdin)
					if err != nil {
						cmd.PrintErrln("Error reading password:", err)
						return fmt.Errorf("failed to read password: %w", err)
					}
					cmd.Println()

					cmd.Print("Confirm password: ")
					confirmPasswordBytes, err := term.ReadPassword(syscall.Stdin)
					if err != nil {
						cmd.PrintErrln("Error reading password confirmation:", err)
						return fmt.Errorf("failed to read password confirmation: %w", err)
					}
					cmd.Println()

					if !bytes.Equal(passwordBytes, confirmPasswordBytes) {
						cmd.PrintErrln("Passwords do not match")
						return fmt.Errorf("passwords do not match")
					}

					for i := range confirmPasswordBytes {
						confirmPasswordBytes[i] = 0
					}

					contentBytes, err = utils.EncryptWithHeader(passwordBytes, contentBytes)
					// clear sensitive data
					defer func() {
						for i := range passwordBytes {
							passwordBytes[i] = 0
						}
					}()

					if err != nil {
						cmd.PrintErrln("Error encrypting data:", err)
						return fmt.Errorf("failed to encrypt data: %w", err)
					}
				}
			}

			if err := utils.WriteToFile(outputFilePath, contentBytes); err != nil {
				cmd.PrintErrln("Error writing to file:", err)
				return fmt.Errorf("failed to write to file: %w", err)
			}

			cmd.Printf("Private key recovered to file (%s) successfully: %s\n", format, outputFilePath)
			return nil
		}
		cmd.Printf("Recovered private key: %s\n", base64.StdEncoding.EncodeToString(privateKeyBytes))
		return nil
	},
}

func init() {
	// Required flags
	Cmd.Flags().String(flagRecoveryKitPath, "", "Local file path to the recovery data file from S3")
	Cmd.Flags().String(flagPrivateKeyPath, "", "File path to RSA-4096 bit private key (hex-encoded DER or encrypted with --encrypt-private-key)")
	Cmd.Flags().String(flagQuorumID, "", "Quorum ID")
	Cmd.Flags().String(flagKeyID, "", "Key ID")

	// Optional flag for key type
	Cmd.Flags().String(flagKeyType, "", "Key algorithm type: SECP256K1 (default) or ED25519")

	if err := Cmd.MarkFlagRequired(flagRecoveryKitPath); err != nil {
		Cmd.PrintErrln("Error marking recovery kit path as required:", err)
		return
	}
	if err := Cmd.MarkFlagRequired(flagPrivateKeyPath); err != nil {
		Cmd.PrintErrln("Error marking private key path as required:", err)
		return
	}
	if err := Cmd.MarkFlagRequired(flagQuorumID); err != nil {
		Cmd.PrintErrln("Error marking quorum ID as required:", err)
		return
	}
	if err := Cmd.MarkFlagRequired(flagKeyID); err != nil {
		Cmd.PrintErrln("Error marking key ID as required:", err)
		return
	}

	// Optional flags
	Cmd.Flags().String(flagOutputFile, "", "File path to save the recovered private key")
	Cmd.Flags().Bool(flagEncryptOutput, true, "Encrypt the output file using the private key")

	Cmd.MarkFlagsRequiredTogether(
		flagPrivateKeyPath,
		flagRecoveryKitPath,
		flagQuorumID,
		flagKeyID,
	)
}
