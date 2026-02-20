# Contributing to Wallet Recovery CLI

Thank you for your interest in contributing!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/palisadeinc/wallet-recovery-cli.git
   cd wallet-recovery-cli
   ```

2. Install Go 1.24+ from https://go.dev/dl/

3. Install development tools:
   ```bash
   go install mvdan.cc/gofumpt@latest
   go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
   ```

4. Build and test:
   ```bash
   go build -o recovery ./main.go
   go test ./...
   ```

## Pre-Commit Checks

Before committing, run:
```bash
go mod tidy && go generate ./... && go test ./... && golangci-lint run ./... && gofumpt -w .
```

All checks must pass before a PR can be merged.

## Pull Request Process

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes with appropriate tests
4. Ensure all pre-commit checks pass
5. Submit a PR with a clear description

## Code Style

- Follow standard Go conventions
- Use `gofumpt` for formatting (stricter than `gofmt`)
- Use `fmt.Errorf("context: %w", err)` for error wrapping
- Write table-driven tests

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For security vulnerabilities, see SECURITY.md

