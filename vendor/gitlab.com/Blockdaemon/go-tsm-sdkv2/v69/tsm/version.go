package tsm

import (
	"context"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/transport"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/version"
	"log"
	"net/http"
	"regexp"
)

var versionRegex, _ = regexp.Compile(`^([0-9]+)\.([0-9]+)$`)

// VersionInformation contains information about the version of the MPC node.
//
// The TSM uses semantic versioning, where a version is on the form "x.y.z" where
//   - x is the major version; an increase indicates changes that may break backwards compatibility
//   - y is the minor version; increased when new features are introduced but backwards compatibility is maintained
//   - z is the patch version; increased on improvements and fixes that does not affect compatibility
//
// The TSM version consists of an overall version along with versions for different parts of the system.
type VersionInformation struct {

	// The overall TSM version.
	// This is a summary of all the other versions listed here. If there is a major increase
	// in any of other versions, there will be a major increase in Version, too. If the other versions
	// contain only minor increases, then Version will contain a minor increase.
	// Finally, if there was only patch updates, Version only has an increase in its patch version.
	Version string

	// The version of the programming and configuration interface for the SDK.
	// Bumped on major and minor changes to any exported function or type in the SDK package(s)
	// and any change to the way the SDK is configured (e.g., environment variables or credentials file).
	// This includes all SDKs: go, PKCS#11, node.js, wasm, JCE, etc.
	// If there is a major bump here, an app that calls the SDK may need to make changes to its code to use the SDK.
	ClientAPI string

	// The version of the client communication interface between client (SDK) and an MPC node.
	// This is increased on major and minor changes to path, http method, client/server protocol,
	// transport object, etc. If there is no major bump here, a client app can upgrade its SDK and still
	// communicate with older nodes (and vice versa).
	ClientCommunication string

	// The version of the communication interface between MPC nodes.
	// Bumped on changes to the connections between MPC nodes are established, changes to how the MPC nodes
	// communicate in MPC protocols, how and when MPC session metadata is exchanged and checked, etc.
	// If no major bump here, an MPC node that upgrades can still expect to complete an MPC protocol with older nodes.
	NodeCommunication string

	// The version of the MPC node configuration interface.
	// Bumped on any major or minor change to the configuration of an MPC node.
	NodeConfiguration string
}

// TSMVersion returns information about the version of the TSM to which the SDK is connected.
func (c *Client) TSMVersion() (*VersionInformation, error) {
	response, err := c.node.call(context.TODO(), http.MethodGet, "/version", &SessionConfig{}, c.node.sendRequest, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch TSM version: %w", err)
	}
	var jsonResponse transport.Version
	if err = unmarshalJSON(response, &jsonResponse); err != nil {
		return nil, fmt.Errorf("unable to parse version: %w", err)
	}

	tsmVersion := VersionInformation(jsonResponse)
	checkVersionCompatibility(c.SDKVersion(), &tsmVersion)

	return &tsmVersion, nil
}

// SDKVersion returns information about the version of the SDK. This is the version of the TSM when the SDK was built.
func (c *Client) SDKVersion() *VersionInformation {
	return &VersionInformation{
		Version:             version.TSM,
		ClientAPI:           version.CLIENT_API,
		ClientCommunication: version.CLIENT_COMMUNICATION,
		NodeCommunication:   version.NODE_COMMUNICATION,
		NodeConfiguration:   version.NODE_CONFIGURATION,
	}
}

func checkVersionCompatibility(sdkVersion, tsmVersion *VersionInformation) {
	sdkClientCommVersion := versionRegex.FindStringSubmatch(sdkVersion.ClientCommunication)
	tsmClientCommVersion := versionRegex.FindStringSubmatch(tsmVersion.ClientCommunication)
	if len(sdkClientCommVersion) != 3 || len(tsmClientCommVersion) != 3 {
		return
	}
	if sdkClientCommVersion[1] != tsmClientCommVersion[1] {
		log.Printf("Major version mismatch in client communication between TSM (%s) and SDK (%s). Consider upgrading so the major versions are equal, otherwise some operations might fail", tsmClientCommVersion[0], sdkClientCommVersion[0])
	}
}
