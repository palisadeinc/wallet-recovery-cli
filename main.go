// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/palisadeinc/wallet-recovery-cli/cmd"
)

// Version is the version of the wallet-recovery-cli tool.
// It can be set at build time using: go build -ldflags="-X 'main.Version=v1.0.0'"
var Version = "dev"

func main() {
	cmd.SetVersion(Version)
	cmd.Execute()
}
