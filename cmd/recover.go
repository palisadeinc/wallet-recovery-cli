package cmd

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/palisadeinc/mpc-recovery/models"
	"github.com/palisadeinc/mpc-recovery/utils"
	"github.com/spf13/cobra"
	"gitlab.com/sepior/go-tsm-sdkv2/tsm"
	"strings"
)

const flagRecoveryKitPath = "recovery-kit-file"
const flagPrivateKeyPath = "private-key-file"
const flagQuorumID = "quorum-id"
const flagKeyID = "key-id"

var recoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover a private key from recovery data",
	Long:  "Recover a private key from recovery data using cryptographic primitives.",
	Run: func(cmd *cobra.Command, args []string) {
		recoveryKitPath, err := cmd.Flags().GetString(flagRecoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving file path:", err)
			return
		}

		privateKeyPath, err := cmd.Flags().GetString(flagPrivateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error retrieving private key:", err)
			return
		}

		if recoveryKitPath == "" || privateKeyPath == "" {
			cmd.PrintErrln("File path and private key are required.")
			return
		}

		recoveryKitBase64Bytes, err := utils.OpenFile(recoveryKitPath)
		if err != nil {
			cmd.PrintErrln("Error opening file:", err)
			return
		}

		privateKeyBytes, err := utils.OpenFile(privateKeyPath)
		if err != nil {
			cmd.PrintErrln("Error opening private key file:", err)
			return
		}

		privateKeyHex := string(privateKeyBytes)
		// Remove all whitespace characters
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\n", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\r", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, " ", "")
		privateKeyHex = strings.ReplaceAll(privateKeyHex, "\t", "")

		privateKeyDerBytes, err := hex.DecodeString(privateKeyHex)
		if err != nil {
			cmd.PrintErrln("Error decoding private key:", err)
			return
		}

		ersPrivateKey, err := x509.ParsePKCS8PrivateKey(privateKeyDerBytes)
		if err != nil {
			// try using pkcs1
			ersPrivateKey, err = x509.ParsePKCS1PrivateKey(privateKeyDerBytes)
			if err != nil {
				cmd.PrintErrln("Error parsing private key:", err)
				return
			}
		}

		ersRSAPrivateKey, ok := ersPrivateKey.(*rsa.PrivateKey)
		if !ok {
			cmd.PrintErrln("Invalid private key, expected PKCS8 Private Key")
			return
		}

		recoveryKitBytes, err := base64.StdEncoding.DecodeString(string(recoveryKitBase64Bytes))
		if err != nil {
			cmd.PrintErrln("Error decoding base64 recoveryKit:", err)
			return
		}

		var recoveryKit models.RecoveryDataObject
		if err := json.Unmarshal(recoveryKitBytes, &recoveryKit); err != nil {
			cmd.PrintErrln("Error unmarshalling recovery kit:", err)
			return
		}

		// check if recoveryKit.RecoveryPublicKeyHex belongs to the private key
		// Generate the RSA public key from the private key
		ersPublicKey := ersRSAPrivateKey.Public().(*rsa.PublicKey)
		ersPublicKeyBytes, err := x509.MarshalPKIXPublicKey(ersPublicKey)
		if err != nil {
			cmd.PrintErrln("Error marshalling public key:", err)
			return
		}

		ersPublicKeyHex := hex.EncodeToString(ersPublicKeyBytes)
		if recoveryKit.RecoveryPublicKeyHex != ersPublicKeyHex {
			cmd.PrintErrln("Recovery public key does not match the private key.")
			return
		}
		cmd.Println("Recovery public key matches the private key.")

		//walletPublicKeyBytes, err := base64.StdEncoding.DecodeString(recoveryKit.WalletPublicKeyBase64)
		//if err != nil {
		//	cmd.PrintErrln("Error decoding wallet public key:", err)
		//	return
		//}

		recoveryDataBytes, err := base64.StdEncoding.DecodeString(recoveryKit.PartialRecoveryDataBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding recovery data:", err)
			return
		}

		quorumIDStr, err := cmd.Flags().GetString(flagQuorumID)
		if err != nil {
			cmd.PrintErrln("Error retrieving quorum ID:", err)
			return
		}

		quorumID, err := uuid.Parse(quorumIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing quorum ID:", err)
			return
		}

		keyIDStr, err := cmd.Flags().GetString(flagKeyID)
		if err != nil {
			cmd.PrintErrln("Error retrieving key ID:", err)
			return
		}

		keyID, err := uuid.Parse(keyIDStr)
		if err != nil {
			cmd.PrintErrln("Error parsing key ID:", err)
			return
		}

		cmd.Println("root wallet public key:", recoveryKit.WalletRootPublicKeyPkixBase64)

		rootWalletKeyPkix, err := base64.StdEncoding.DecodeString(recoveryKit.WalletRootPublicKeyPkixBase64)
		if err != nil {
			cmd.PrintErrln("Error decoding wallet root public key:", err)
			return
		}

		ersLabel := sha256.Sum256([]byte(fmt.Sprintf("%s-%s", quorumID, keyID)))
		if err := tsm.ECDSAValidateRecoveryData(recoveryDataBytes, rootWalletKeyPkix, ersPublicKey, ersLabel[:]); err != nil {
			cmd.PrintErrln("Recovery kit was not valid:", err)
			return
		}

		privateKey, err := tsm.ECDSARecoverPrivateKey(recoveryDataBytes, ersRSAPrivateKey, ersLabel[:])
		if err != nil {
			cmd.PrintErrln("Error recovering private key:", err)
			return
		}

		cmd.Println("Recovered private key:")
		cmd.Println(base64.StdEncoding.EncodeToString(privateKey.PrivateKey))
	},
}

func init() {
	recoverCmd.Flags().String(flagRecoveryKitPath, "", "Local file path to the recovery data file from S3")
	recoverCmd.Flags().String(flagPrivateKeyPath, "", "File path to hex formatted, DER encoded RSA-4096 bit private key")
	recoverCmd.Flags().String(flagQuorumID, "", "Quorum ID")
	recoverCmd.Flags().String(flagKeyID, "", "Key ID")
	recoverCmd.MarkFlagsRequiredTogether(
		flagPrivateKeyPath,
		flagRecoveryKitPath,
		flagQuorumID,
		flagKeyID,
	)
}

// ASN.1 structures needed for parsing PKIX public key
type publicKeyInfo struct {
	Algorithm algorithmIdentifier
	PublicKey asn1.BitString
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

func convertExternalToInternal(derBytes []byte) ([]byte, error) {
	// Parse the DER-encoded SubjectPublicKeyInfo structure
	var pubKeyInfo publicKeyInfo
	if _, err := asn1.Unmarshal(derBytes, &pubKeyInfo); err != nil {
		return nil, fmt.Errorf("error parsing ASN.1 structure: %w", err)
	}

	// For secp256k1, the BitString should contain the raw key data
	// with a leading byte '04' (uncompressed point format),
	// followed by the X and Y coordinates (32 bytes each)
	rawKeyBytes := pubKeyInfo.PublicKey.Bytes

	// Verify that we have the expected format (04 + 64 bytes)
	if len(rawKeyBytes) != 65 || rawKeyBytes[0] != 0x04 {
		return nil, fmt.Errorf("unexpected public key format, not an uncompressed EC point")
	}

	return rawKeyBytes, nil
}
