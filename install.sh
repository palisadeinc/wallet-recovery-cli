#!/bin/bash
# Wallet Recovery CLI Installer
# Usage: curl -sSfL https://raw.githubusercontent.com/palisadeinc/wallet-recovery-cli/main/install.sh | bash

set -e

REPO="palisadeinc/wallet-recovery-cli"
BINARY_NAME="recovery"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

case "$OS" in
  linux) ;;
  darwin) ;;
  mingw*|msys*|cygwin*) OS="windows"; BINARY_NAME="recovery.exe" ;;
  *) echo "Unsupported OS: $OS"; exit 1 ;;
esac

# Get latest release
echo "Fetching latest release..."
LATEST=$(curl -sSf "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$LATEST" ]; then
  echo "Error: Could not determine latest version"
  exit 1
fi

echo "Installing ${BINARY_NAME} ${LATEST} for ${OS}/${ARCH}..."

# Download binary
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY_NAME}-${OS}-${ARCH}"
if [ "$OS" = "windows" ]; then
  DOWNLOAD_URL="${DOWNLOAD_URL}.exe"
fi

TMP_FILE=$(mktemp)
curl -sSfL "$DOWNLOAD_URL" -o "$TMP_FILE"
chmod +x "$TMP_FILE"

# Install
if [ -w "$INSTALL_DIR" ]; then
  mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "$TMP_FILE" "${INSTALL_DIR}/${BINARY_NAME}"
fi

echo "Successfully installed ${BINARY_NAME} to ${INSTALL_DIR}/${BINARY_NAME}"
echo "Run 'recovery --help' to get started"

