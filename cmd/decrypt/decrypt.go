package decrypt

import (
	"syscall"

	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagEncryptedPrivateKeyFile = "encrypted-private-key-file"
const flagDecryptedOutputFile = "decrypted-output-file"

var Cmd = &cobra.Command{
	Use:   "decrypt",
	Short: "Decrypt an encrypted recovery private key file",
	Long:  "Decrypt an encrypted private key file generated using the recover command.",
	Run: func(cmd *cobra.Command, args []string) {
		// validate inputs
		encryptedPrivateKeyFilePath, err := cmd.Flags().GetString(flagEncryptedPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypted private key file path:", err)
			return
		}

		decryptedOutputFilePath, err := cmd.Flags().GetString(flagDecryptedOutputFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving decrypted output file path:", err)
			return
		}

		if decryptedOutputFilePath == encryptedPrivateKeyFilePath {
			cmd.PrintErrln("Decrypted output file path cannot be the same as the encrypted private key file path")
			return
		}

		cmd.Print("Enter encryption password: ")
		passwordBytes, err := term.ReadPassword(syscall.Stdin)
		if err != nil {
			cmd.PrintErrln("Error reading password:", err)
			return
		}
		cmd.Println()

		encryptedPrivateKeyFileBytes, err := utils.OpenReadOnlyFile(encryptedPrivateKeyFilePath)
		if err != nil {
			cmd.PrintErrln("Error opening encrypted private key file:", err)
			return
		}

		contentBytes, err := utils.DecryptData(passwordBytes, encryptedPrivateKeyFileBytes)
		if err != nil {
			cmd.PrintErrln("Error decrypting private key file:", err)
			return
		}

		if err := utils.WriteToFile(decryptedOutputFilePath, contentBytes); err != nil {
			cmd.PrintErrln("Error writing decrypted private key file:", err)
			return
		}

		cmd.Println("Decrypted private key file saved successfully")
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
