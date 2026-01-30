package validate_key

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"syscall"

	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagPrivateKeyFile = "private-key-file"

var Cmd = &cobra.Command{
	Use:   "validate-private-key",
	Short: "Validate password for an encrypted private key",
	Long:  "Validate that a password can decrypt an encrypted RSA private key file without modifying the file.",
	Run: func(cmd *cobra.Command, args []string) {
		privateKeyFilePath, err := cmd.Flags().GetString(flagPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return
		}

		// Read the file
		fileBytes, err := utils.OpenReadOnlyFile(privateKeyFilePath)
		if err != nil {
			cmd.PrintErrln("Error reading private key file:", err)
			return
		}
		defer utils.ClearSensitiveBytes(fileBytes)

		// Check if the file is encrypted (has PKE1 header)
		if !utils.HasEncryptionHeader(fileBytes) {
			// Not encrypted - check if it's a valid plain hex private key
			if isValidPlainPrivateKey(fileBytes) {
				cmd.Println("Private key file is not encrypted. No password validation needed.")
				return
			}
			cmd.PrintErrln("Not a valid private key file: file is neither encrypted nor a valid hex-encoded RSA private key")
			return
		}

		// File is encrypted - prompt for password
		cmd.Print("Enter password to validate: ")
		passwordBytes, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			cmd.PrintErrln("\nError reading password:", err)
			return
		}
		cmd.Println()

		// Attempt to decrypt
		decryptedBytes, err := utils.DecryptWithHeader(passwordBytes, fileBytes)
		if err != nil {
			cmd.PrintErrln("Validation failed: incorrect password or corrupted file")
			return
		}
		defer utils.ClearSensitiveBytes(decryptedBytes)

		// Validate the decrypted content is a valid RSA private key
		if !isValidPlainPrivateKey(decryptedBytes) {
			cmd.PrintErrln("Validation failed: decrypted content is not a valid RSA private key")
			return
		}

		cmd.Println("Validation successful: password is correct and private key is valid")
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
