package recover

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"syscall"

	"github.com/google/uuid"
	"github.com/palisadeinc/mpc-recovery/models"
	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagOutputFile = "output-file"
const flagEncryptOutput = "encrypt-output"
const flagRecoveryKitPath = "recovery-kit-file"
const flagPrivateKeyPath = "private-key-file"
const flagQuorumID = "quorum-id"
const flagKeyID = "key-id"
const flagKeyType = "key-type"

var Cmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover a private key from recovery data",
	Long:  "Recover a private key from recovery data using cryptographic primitives.",
	Run: func(cmd *cobra.Command, args []string) {
		recoveryKitPath, err := cmd.Flags().GetString(flagRecoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving file path:", err)
			return
		}

		privateKeyPath, err := cmd.Flags().GetString(flagPrivateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key:", err)
			return
		}

		if recoveryKitPath == "" || privateKeyPath == "" {
			cmd.PrintErrln("File path and private key are required.")
			return
		}

		recoveryKitBase64Bytes, err := utils.OpenReadOnlyFile(recoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error opening file:", err)
			return
		}

		privateKeyBytes, err := utils.OpenReadOnlyFile(privateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error opening private key file:", err)
			return
		}

		defer utils.ClearSensitiveBytes(privateKeyBytes)

		privateKeyHex := string(privateKeyBytes)
		// Remove all whitespace characters
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\n", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\r", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, " ", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\t", "")

		privateKeyDerBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			cmd.PrintErrln("Error decoding private key:", err)
			return
		}

		defer utils.ClearSensitiveBytes(privateKeyDerBytes)

		ersPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDerBytes)
		if err != nil {
			// try using pkcs1
			ersPrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDerBytes)
			if err != nil {
				cmd.PrintErrln("Error parsing private key:", err)
				return
			}
		}

		ersRSAPrivateKey, ok := ersPrivateKey.(*rsa.PrivateKey)
		if !ok {
			cmd.PrintErrln("Invalid private key, expected PKCS8 Private Key")
			return
		}

		recoveryKitBytes, err := base64.StdEncoding.DecodeString(string(recoveryKitBase64Bytes))
		if err != nil {
			cmd.PrintErrln("Error decoding base64 recoveryKit:", err)
			return
		}

		defer utils.ClearSensitiveBytes(recoveryKitBytes)

		var recoveryKit models.RecoveryDataObject
		if err := json.Unmarshal(recoveryKitBytes, &recoveryKit); err != nil {
			cmd.PrintErrln("Error unmarshalling recovery kit:", err)
			return
		}

		// check if recoveryKit.RecoveryPublicKeyHex belongs to the private key
		// Generate the RSA public key from the private key
		ersPublicKey := ersRSAPrivateKey.Public().(*rsa.PublicKey)
		ersPublicKeyBytes, err := x509.MarshalPKIXPublicKey(ersPublicKey)
		if err != nil {
			cmd.PrintErrln("Error marshalling public key:", err)
			return
		}

		ersPublicKeyHex := hex.EncodeToString(ersPublicKeyBytes)
		if recoveryKit.RecoveryPublicKeyHex != ersPublicKeyHex {
			cmd.PrintErrln("Recovery public key does not match the private key.")
			return
		}
		cmd.Println("Recovery public key matches the private key.")

		recoveryDataBytes, err := base64.StdEncoding.DecodeString(recoveryKit.PartialRecoveryDataBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding recovery data:", err)
			return
		}

		defer utils.ClearSensitiveBytes(recoveryDataBytes)

		quorumIDStr, err := cmd.Flags().GetString(flagQuorumID)
		if err != nil {
			cmd.PrintErrln("Error retrieving quorum ID:", err)
			return
		}

		quorumID, err := uuid.Parse(quorumIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing quorum ID:", err)
			return
		}

		keyIDStr, err := cmd.Flags().GetString(flagKeyID)
		if err != nil {
			cmd.PrintErrln("Error retrieving key ID:", err)
			return
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing key ID:", err)
			return
		}

		rootWalletKeyPkix, err := base64.StdEncoding.DecodeString(recoveryKit.WalletRootPublicKeyPkixBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding wallet root public key:", err)
			return
		}

		defer utils.ClearSensitiveBytes(rootWalletKeyPkix)

		// Check key type flag
		keyType, err := cmd.Flags().GetString(flagKeyType)
		if err != nil {
			cmd.PrintErrln("Error retrieving key type:", err)
			return
		}

		// Default to SECP256K1 if not specified (for backward compatibility)
		if keyType == "" {
			keyType = string(models.KeyAlgorithmSECP256K1)
		}

		// Check if recovery kit specifies key algorithm
		if recoveryKit.KeyAlgorithm != "" {
			// If both are specified, they must match
			if keyType != string(recoveryKit.KeyAlgorithm) {
				cmd.PrintErrln(
					"Key type mismatch: flag specifies", keyType, "but recovery kit specifies",
					recoveryKit.KeyAlgorithm,
				)
				return
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
				return
			}

			defer utils.ClearSensitiveBytes(privateKeyBytes)

			// Display both Ethereum and XRP addresses for SECP256K1 keys
			ethereumAddress, err := utils.GetEthereumAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting Ethereum address:", err)
				return
			}
			cmd.Printf("Ethereum address: %s\n", ethereumAddress)

			xrpAddress, err := utils.GetXRPAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting XRP address:", err)
				return
			}
			cmd.Printf("XRP address: %s\n", xrpAddress)

		case models.KeyAlgorithmED25519:
			privateKeyBytes, err = utils.RecoverED25519PrivateKey(
				recoveryDataBytes, rootWalletKeyPkix, quorumID, keyID, ersRSAPrivateKey, ersPublicKey,
			)
			if err != nil {
				cmd.PrintErrln("Error recovering ED25519 private key:", err)
				return
			}

			defer utils.ClearSensitiveBytes(privateKeyBytes)

			solanaAddress, err := utils.GetSolanaAddressFromPrivateKeyBytes(privateKeyBytes)
			if err != nil {
				cmd.PrintErrln("Error getting Solana address:", err)
				return
			}

			cmd.Printf("Solana address: %s\n", solanaAddress)

		default:
			cmd.PrintErrln("Unsupported key type:", keyType)
			return
		}

		fileOutput := cmd.Flags().Changed(flagOutputFile)
		if fileOutput {
			outputFilePath, err := cmd.Flags().GetString(flagOutputFile)
			if err != nil {
				cmd.PrintErrln("Error retrieving output file path:", err)
				return
			}

			cmd.Println("Writing private key to file...", outputFilePath)
			contentBytes := privateKeyBytes
			format := "plain"
			if encryptOutput := cmd.Flags().Changed(flagEncryptOutput); encryptOutput {
				format = "encrypted"
				encryptOutput, err = cmd.Flags().GetBool(flagEncryptOutput)
				if err != nil {
					cmd.PrintErrln("Error retrieving encrypt output flag:", err)
					return
				}

				if encryptOutput {
					// Prompt for password
					cmd.Print("Enter password for encryption: ")
					passwordBytes, err := term.ReadPassword(syscall.Stdin)
					if err != nil {
						cmd.PrintErrln("Error reading password:", err)
						return
					}
					cmd.Println()

					cmd.Print("Confirm password: ")
					confirmPasswordBytes, err := term.ReadPassword(syscall.Stdin)
					if err != nil {
						cmd.PrintErrln("Error reading password confirmation:", err)
						return
					}
					cmd.Println()

					if !bytes.Equal(passwordBytes, confirmPasswordBytes) {
						cmd.PrintErrln("Passwords do not match")
						return
					}

					for i := range confirmPasswordBytes {
						confirmPasswordBytes[i] = 0
					}

					contentBytes, err = utils.EncryptData(passwordBytes, contentBytes)
					// clear sensitive data
					defer func() {
						for i := range passwordBytes {
							passwordBytes[i] = 0
						}
					}()

					if err != nil {
						cmd.PrintErrln("Error encrypting data:", err)
						return
					}
				}
			}

			if err := utils.WriteToFile(outputFilePath, contentBytes); err != nil {
				cmd.PrintErrln("Error writing to file:", err)
				return
			}

			cmd.Printf("Private key recovered to file (%s) successfully: %s\n", format, outputFilePath)
			return
		} else {
			cmd.Printf("Recovered private key: %s\n", base64.StdEncoding.EncodeToString(privateKeyBytes))
		}
	},
}

func init() {
	// Required flags
	Cmd.Flags().String(flagRecoveryKitPath, "", "Local file path to the recovery data file from S3")
	Cmd.Flags().String(flagPrivateKeyPath, "", "File path to hex formatted, DER encoded RSA-4096 bit private key")
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
