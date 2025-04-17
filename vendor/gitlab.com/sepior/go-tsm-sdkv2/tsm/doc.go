// Package tsm contains the Go version of the Blockdaemon Builder Vault SDKv2.
//
// Refer to the documentation at https://builder-vault-tsm.docs.blockdaemon.com/docs for more information about how to
// use the SDK.
//
// # Example Usage
//
//	configuration := &tsm.Configuration{
//	    URL:    "https://tsm-node-X.example.com",
//	    APIKey: "api-key-for-node-X",
//	}
//
//	client, err := tsm.NewClient(configuration)
//	if err != nil {
//	    log.Fatalf("an error occurred: %s", err)
//	}
//
//	// All nodes must agree on this session ID
//	sessionID := tsm.GenerateSessionID()
//
//	// We want to start a session with players 0, 1 and 2
//	sessionConfig := tsm.NewSessionConfig(sessionID, []int{0, 1, 2}, nil)
//
//	threshold := 2  // The security threshold to use for the new key.
//	keyID, err := client.ECDSA().GenerateKey(context, sessionConfig, threshold, "secp256k1", "")
//	...
package tsm
