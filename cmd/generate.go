package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"github.com/spf13/cobra"
	"os"
)

const flagPrivateKeyFile = "private-key-file"
const flagPublicKeyFile = "public-key-file"

var generateRecoveryKeypairCmd = &cobra.Command{
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

		// generate the keypair
		privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			cmd.PrintErrln("Error generating RSA keypair:", err)
			return
		}

		// Convert private key to DER format
		privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
		// Convert to hex string
		privateKeyHex := hex.EncodeToString(privateKeyDER)

		// Extract public key and convert to DER format
		publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		if err != nil {
			cmd.PrintErrln("Error encoding public key:", err)
			return
		}
		// Convert to hex string
		publicKeyHex := hex.EncodeToString(publicKeyDER)

		// write private key to private key file
		privateKeyFile, err := os.OpenFile(privateKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
		if err != nil {
			cmd.PrintErrln("Error creating private key file:", err)
			return
		}
		defer privateKeyFile.Close()

		if _, err := privateKeyFile.WriteString(privateKeyHex); err != nil {
			cmd.PrintErrln("Error writing private key to file:", err)
			return
		}

		// write public key to public key file
		publicKeyFile, err := os.OpenFile(publicKeyFilePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
		if err != nil {
			cmd.PrintErrln("Error creating public key file:", err)
			return
		}
		defer publicKeyFile.Close()

		if _, err := publicKeyFile.WriteString(publicKeyHex); err != nil {
			cmd.PrintErrln("Error writing public key to file:", err)
			return
		}

	},
}

func init() {
	generateRecoveryKeypairCmd.Flags().String(flagPrivateKeyFile, "", "File path to save the private key. Must not exist.")
	generateRecoveryKeypairCmd.Flags().String(flagPublicKeyFile, "", "File path to save the public key. Must not exist.")
	generateRecoveryKeypairCmd.MarkFlagsRequiredTogether(flagPrivateKeyFile, flagPublicKeyFile)
}
