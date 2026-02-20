# Wallet Recovery CLI Development

## Overview
The wallet-recovery CLI is a standalone Go tool for MPC wallet recovery operations. It generates RSA keypairs, recovers private keys from backup data, and handles encrypted key files.

## Language & Tools

| Tool | Version | Purpose |
|------|---------|---------|
| Go | 1.24+ | Language runtime |
| gofumpt | latest | Code formatting (stricter than gofmt) |
| golangci-lint | v1.64+ | Linting |
| gomock | latest | Mock generation for testing |

## Pre-Commit Checks
Run from the `wallet-recovery-cli/` directory:
```bash
go mod tidy && go generate ./... && go test ./... && golangci-lint run ./... && gofumpt -w .
```

**ALL linting issues MUST be fixed before a PR can be merged. No exceptions.**

## Project Structure
```
wallet-recovery-cli/
├── main.go                 # Entry point
├── cmd/
│   ├── root.go             # Cobra root command, registers subcommands
│   ├── generate/           # generate-recovery-keypair command
│   ├── recover/            # recover command
│   ├── decrypt/            # decrypt command
│   ├── print_address/      # print-address command
│   └── validate_key/       # validate-private-key command
├── models/                 # Data structures
├── utils/                  # Shared utilities (crypto, file, encryption)
├── testdata/               # Test fixtures (sample keys, recovery kits)
├── vendor/                 # Vendored dependencies
├── go.mod
└── go.sum
```

## Command Structure Pattern
Each command lives in its own package under `cmd/<command-name>/`:

```go
package mycommand

import "github.com/spf13/cobra"

const flagMyFlag = "my-flag"

var Cmd = &cobra.Command{
    Use:   "my-command",
    Short: "Short description",
    Long:  "Longer description of the command.",
    Run: func(cmd *cobra.Command, args []string) {
        // Implementation
    },
}

func init() {
    Cmd.Flags().String(flagMyFlag, "", "Flag description")
    if err := Cmd.MarkFlagRequired(flagMyFlag); err != nil {
        Cmd.PrintErrln("Error marking flag as required:", err)
        return
    }
}
```

Register new commands in `cmd/root.go`:
```go
rootCmd.AddCommand(mycommand.Cmd)
```

## Security Practices

### Sensitive Data Handling
- **Always clear sensitive bytes** after use with `utils.ClearSensitiveBytes()`
- Use `defer` to ensure cleanup happens even on error paths
- Clear copies of sensitive data, not just originals

```go
privateKeyDER := x509.MarshalPKCS1PrivateKey(privateKey)
defer utils.ClearSensitiveBytes(privateKeyDER)
```

### Password Input
- Use `term.ReadPassword(syscall.Stdin)` for password input (no echo)
- Clear password bytes after use
- Validate password length before proceeding

```go
cmd.Print("Enter password: ")
passwordBytes, err := term.ReadPassword(syscall.Stdin)
if err != nil {
    cmd.PrintErrln("\nError reading password:", err)
    return
}
cmd.Println()
defer utils.ClearSensitiveBytes(passwordBytes)
```

### File Permissions
- Private key files: `0400` (read-only by owner)
- Use `os.O_EXCL` flag when creating files to prevent overwriting

```go
file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0400)
```

## Error Handling
- Use `cmd.PrintErrln()` for error output in commands
- Use `fmt.Errorf("context: %w", err)` for error wrapping (NOT `pkg/errors`)
- Return early on errors (no nested if/else chains)
- Include context in error messages
- Use `errors.Is()` and `errors.As()` for error checking

```go
// In command handlers
if err != nil {
    cmd.PrintErrln("Error reading file:", err)
    return
}

// In utility functions - wrap with context
if err != nil {
    return fmt.Errorf("failed to parse key file %s: %w", path, err)
}
```

## Key Formats

### RSA Private Keys
- Stored as hex-encoded PKCS1 DER
- Can be encrypted with password (PKE1 header format)

### RSA Public Keys
- Currently output as hex-encoded PKIX DER with `.der` extension
- ~1100 characters for RSA-4096

### Recovered Private Keys
- ECDSA (SECP256K1): 32-byte raw scalar
- ED25519: 32-byte raw scalar

## Pre-Commit Checks
Run from the `wallet-recovery-cli/` directory:
```bash
go mod tidy && go generate ./... && go test ./... && golangci-lint run ./... && gofumpt -w .
```

## Dependencies
- Uses vendored dependencies (`vendor/` directory)
- After adding dependencies: `go mod tidy && go mod vendor`
- TSM SDK from Sepior for MPC operations

## Testing
- Test files use `_test.go` suffix
- Use `testing` package with table-driven tests
- Use gomock for mocking interfaces
- Place test fixtures in `testdata/` directory
- Target >80% code coverage

### Table-Driven Tests Pattern
```go
func TestParseKey(t *testing.T) {
    tests := []struct {
        name    string
        input   []byte
        want    *Key
        wantErr bool
    }{
        {
            name:    "valid RSA key",
            input:   validKeyBytes,
            want:    &Key{Type: "RSA"},
            wantErr: false,
        },
        {
            name:    "invalid key",
            input:   []byte("not a key"),
            want:    nil,
            wantErr: true,
        },
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseKey(tt.input)
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseKey() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ParseKey() = %v, want %v", got, tt.want)
            }
        })
    }
}
```

### Mock Generation
```go
//go:generate mockgen -source=recovery.go -destination=mocks/recovery_mock.go -package=mocks
```

## Common Utilities

### File Operations
- `utils.OpenReadOnlyFile(path)` - Read file contents
- `utils.WriteToFile(path, data)` - Write with proper permissions

### Encryption
- `utils.EncryptWithHeader(password, data)` - Encrypt with PKE1 header
- `utils.DecryptWithHeader(password, data)` - Decrypt PKE1 format
- `utils.HasEncryptionHeader(data)` - Check for PKE1 magic bytes

### Crypto
- `utils.GetEthereumAddressFromPrivateKeyBytes()` - Derive ETH address
- `utils.RecoverECDSAPrivateKey()` - Recover SECP256K1 key
- `utils.RecoverED25519PrivateKey()` - Recover ED25519 key

