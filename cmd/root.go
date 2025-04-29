package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "recovery",
	Short: "A CLI tool for MPC recovery operations",
	Long:  "A Command Line Interface (CLI) tool for performing MPC recovery operations using cryptographic primitives.",
	Run: func(cmd *cobra.Command, args []string) {
		// Default action for the root command
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	viper.SetDefault("license", "apache")

	//rootCmd.AddCommand(genRecoveryKeysCmd)
	rootCmd.AddCommand(recoverCmd)
	rootCmd.AddCommand(generateRecoveryKeypairCmd)
}
