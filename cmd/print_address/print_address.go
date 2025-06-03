package print_address

import (
	"syscall"

	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

const flagPrivateKeyFile = "private-key-file"
const flagEncrypted = "encrypted"

var Cmd = &cobra.Command{
	Use:   "print-address",
	Short: "Print blockchain address associated with recovered private key",
	Long:  "Decrypt an encrypted recovered private key, derive the public key, and print the associated blockchain address.",
	Run: func(cmd *cobra.Command, args []string) {
		// validate inputs
		privateKeyFilePath, err := cmd.Flags().GetString(flagPrivateKeyFile)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key file path:", err)
			return
		}

		var contentBytes []byte
		encrypted, err := cmd.Flags().GetBool(flagEncrypted)
		if err != nil {
			cmd.PrintErrln("Error retrieving encrypted flag:", err)
			return
		}

		if encrypted {
			cmd.Print("Enter encryption password: ")
			passwordBytes, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				cmd.PrintErrln("Error reading password:", err)
				return
			}
			cmd.Println()

			encryptedPrivateKeyFileBytes, err := utils.OpenReadOnlyFile(privateKeyFilePath)
			if err != nil {
				cmd.PrintErrln("Error opening encrypted private key file:", err)
				return
			}

			contentBytes, err = utils.DecryptData(passwordBytes, encryptedPrivateKeyFileBytes)
			if err != nil {
				cmd.PrintErrln("Error decrypting private key file:", err)
				return
			}
		} else {
			contentBytes, err = utils.OpenReadOnlyFile(privateKeyFilePath)
			if err != nil {
				cmd.PrintErrln("Error opening encrypted private key file:", err)
				return
			}
		}

		address, err := utils.GetEthereumAddressFromPrivateKeyBytes(contentBytes)
		if err != nil {
			cmd.PrintErrln("Error getting Ethereum address from private key bytes:", err)
			return
		}

		cmd.Println("EVM-compatible address:", address)
	},
}

func init() {
	Cmd.Flags().String(flagPrivateKeyFile, "", "Path to file containing encrypted private key. Must exist and be readable.")
	Cmd.Flags().Bool(flagEncrypted, false, "Whether the private key file is encrypted.")
	Cmd.MarkFlagRequired(flagPrivateKeyFile)
	Cmd.MarkFlagsRequiredTogether(flagPrivateKeyFile)
}
