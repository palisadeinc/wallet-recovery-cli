package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Encode(t *testing.T) {
	pk := "047aab3a43ea898b3194e833ec30ff3cf0f063a7518ab5b4a1bf0643dfe39a9504eff791e871f149208b4b8a6a05344f871937286aca933f57199832023c92d3a1"
	b, err := hex.DecodeString(pk)
	require.NoError(t, err)
	fmt.Println(base64.StdEncoding.EncodeToString(b))
}
