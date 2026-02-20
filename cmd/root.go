// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"
	"os"

	"github.com/palisadeinc/wallet-recovery-cli/cmd/decrypt"
	"github.com/palisadeinc/wallet-recovery-cli/cmd/generate"
	"github.com/palisadeinc/wallet-recovery-cli/cmd/print_address"
	"github.com/palisadeinc/wallet-recovery-cli/cmd/recover"
	"github.com/palisadeinc/wallet-recovery-cli/cmd/validate_key"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   "recovery",
	Short: "A CLI tool for MPC recovery operations",
	Long:  "A Command Line Interface (CLI) tool for performing MPC recovery operations using cryptographic primitives.",
	Run: func(cmd *cobra.Command, _ []string) {
		// Default action for the root command
		err := cmd.Help()
		if err != nil {
			cmd.PrintErrln(err)
			os.Exit(1)
		}
	},
}

// SetVersion sets the version for the CLI tool.
func SetVersion(v string) {
	rootCmd.Version = v
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	viper.SetDefault("license", "apache")

	// Add version flag
	rootCmd.Flags().BoolP("version", "v", false, "Print version information")

	rootCmd.AddCommand(recover.Cmd)
	rootCmd.AddCommand(generate.Cmd)
	rootCmd.AddCommand(decrypt.Cmd)
	rootCmd.AddCommand(print_address.Cmd)
	rootCmd.AddCommand(validate_key.Cmd)
}
