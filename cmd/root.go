package cmd

import (
	"fmt"
	"os"

	"github.com/palisadeinc/mpc-recovery/cmd/decrypt"
	"github.com/palisadeinc/mpc-recovery/cmd/generate"
	"github.com/palisadeinc/mpc-recovery/cmd/print_address"
	"github.com/palisadeinc/mpc-recovery/cmd/recover"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "recovery",
	Short: "A CLI tool for MPC recovery operations",
	Long:  "A Command Line Interface (CLI) tool for performing MPC recovery operations using cryptographic primitives.",
	Run: func(cmd *cobra.Command, args []string) {
		// Default action for the root command
		err := cmd.Help()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
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

	rootCmd.AddCommand(recover.Cmd)
	rootCmd.AddCommand(generate.Cmd)
	rootCmd.AddCommand(decrypt.Cmd)
	rootCmd.AddCommand(print_address.Cmd)
}
