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

	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagPrivateKeyFile = "private-key-file"
const flagPublicKeyFile = "public-key-file"
const flagEncryptPrivateKey = "encrypt-private-key"

var Cmd = &cobra.Command{
	Use:   "generate-recovery-keypair",
	Short: "Generate a recovery keypair",
	Long:  "Generate RSA 4096-bit keypair for MPC recovery.",
	Run: func(cmd *cobra.Command, args []string) {
		// validate inputs
		privateKeyFilePath, err := cmd.Flags().GetString(flagPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return
		}

		publicKeyFilePath, err := cmd.Flags().GetString(flagPublicKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return
		}

		encryptPrivateKey, err := cmd.Flags().GetBool(flagEncryptPrivateKey)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypt private key flag:", err)
			return
		}

		// Collect password BEFORE key generation to fail fast and minimize sensitive data lifetime
		var passwordBytes []byte
		if encryptPrivateKey {
			fmt.Fprint(cmd.OutOrStdout(), "Enter password to encrypt private key: ")
			passwordBytes, err = term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("\nError reading password:", err)
				return
			}
			fmt.Fprintln(cmd.OutOrStdout())

			fmt.Fprint(cmd.OutOrStdout(), "Confirm password: ")
			confirmPasswordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				utils.ClearSensitiveBytes(passwordBytes)
				cmd.PrintErrln("\nError reading password confirmation:", err)
				return
			}
			fmt.Fprintln(cmd.OutOrStdout())

			if !bytes.Equal(passwordBytes, confirmPasswordBytes) {
				utils.ClearSensitiveBytes(passwordBytes)
				utils.ClearSensitiveBytes(confirmPasswordBytes)
				cmd.PrintErrln("Passwords do not match")
				return
			}
			utils.ClearSensitiveBytes(confirmPasswordBytes)
		}

		// generate the keypair
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			utils.ClearSensitiveBytes(passwordBytes)
			cmd.PrintErrln("Error generating RSA keypair:", err)
			return
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
			return
		}
		// Convert to hex string
		publicKeyHex := hex.EncodeToString(publicKeyDER)

		// write private key to private key file
		privateKeyFile, err := os.OpenFile(privateKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
		if err != nil {
			utils.ClearSensitiveBytes(passwordBytes)
			cmd.PrintErrln("Error creating private key file:", err)
			return
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
				return
			}

			if _, err := privateKeyFile.Write(encryptedBytes); err != nil {
				cmd.PrintErrln("Error writing encrypted private key to file:", err)
				return
			}
		} else {
			if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
				cmd.PrintErrln("Error writing private key to file:", err)
				return
			}
		}

		// write public key to public key file
		publicKeyFile, err := os.OpenFile(publicKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
		if err != nil {
			cmd.PrintErrln("Error creating public key file:", err)
			return
		}
		defer func() {
			if err := publicKeyFile.Close(); err != nil {
				cmd.PrintErrln("Error closing public key file:", err)
			}
		}()

		if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
			cmd.PrintErrln("Error writing public key to file:", err)
			return
		}

	},
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "File path to save the private key. Must not exist.")
	Cmd.Flags().String(flagPublicKeyFile, "", "File path to save the public key. Must not exist.")
	Cmd.Flags().Bool(flagEncryptPrivateKey, false, "Encrypt the private key with a password")
	Cmd.MarkFlagsRequiredTogether(flagPrivateKeyFile, flagPublicKeyFile)
}
