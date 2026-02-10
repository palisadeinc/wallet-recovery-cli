// Copyright 2024 Palisade
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"testing"
)

// FuzzValidateFilePath tests path validation with random inputs
// This fuzz test ensures ValidateFilePath doesn't panic on malformed input
func FuzzValidateFilePath(f *testing.F) {
	// Add seed corpus with various test cases
	f.Add("/valid/path")
	f.Add("../../../etc/passwd")
	f.Add("path\x00with\x00nulls")
	f.Add("")
	f.Add(".")
	f.Add("..")
	f.Add("/")
	f.Add("//")
	f.Add("///")
	f.Add("valid_file.txt")
	f.Add("./relative/path")
	f.Add("../relative/path")
	f.Add("path with spaces")
	f.Add("path\twith\ttabs")
	f.Add("path\nwith\nnewlines")
	f.Add("path\rwith\rcarriage")
	f.Add("very/long/" + string(make([]byte, 1000)))
	f.Add("path\x01\x02\x03")
	f.Add("path\xff\xfe\xfd")

	f.Fuzz(func(_ *testing.T, path string) {
		// Should not panic - ValidateFilePath should handle any input gracefully
		_ = ValidateFilePath(path) //nolint:errcheck // fuzz test
	})
}

// FuzzValidateUUID tests UUID validation with random inputs
// This fuzz test ensures ValidateUUID doesn't panic on malformed input
func FuzzValidateUUID(f *testing.F) {
	// Add seed corpus with various UUID formats and invalid inputs
	f.Add("550e8400-e29b-41d4-a716-446655440000")
	f.Add("550e8400e29b41d4a716446655440000")
	f.Add("urn:uuid:550e8400-e29b-41d4-a716-446655440000")
	f.Add("{550e8400-e29b-41d4-a716-446655440000}")
	f.Add("")
	f.Add("invalid-uuid")
	f.Add("550e8400-e29b-41d4-a716")
	f.Add("550e8400-e29b-41d4-a716-446655440000-extra")
	f.Add("not-a-uuid-at-all")
	f.Add("00000000-0000-0000-0000-000000000000")
	f.Add("ffffffff-ffff-ffff-ffff-ffffffffffff")
	f.Add("550e8400-e29b-41d4-a716-44665544000")
	f.Add("550e8400-e29b-41d4-a716-4466554400000")
	f.Add("550e8400-e29b-41d4-a716-44665544000g")
	f.Add("550e8400-e29b-41d4-a716-44665544000\x00")
	f.Add("550e8400-e29b-41d4-a716-44665544000\n")
	f.Add("550e8400-e29b-41d4-a716-44665544000 ")
	f.Add("550e8400-e29b-41d4-a716-44665544000\t")

	f.Fuzz(func(_ *testing.T, uuidStr string) {
		// Should not panic - ValidateUUID should handle any input gracefully
		_ = ValidateUUID(uuidStr, "test_field") //nolint:errcheck // fuzz test
	})
}
