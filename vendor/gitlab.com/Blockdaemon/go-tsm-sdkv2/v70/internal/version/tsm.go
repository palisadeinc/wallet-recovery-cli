package version

// TSM is changed in the release jobs on gitlab and contains the tag of the release.
const TSM string = "70.1.0"

// These values are also changed in the release jobs and contain the version number of the corresponding component.
const (
	CLIENT_COMMUNICATION string = "30.2"
	CLIENT_API           string = "61.3"
	NODE_COMMUNICATION   string = "34.1"
	NODE_CONFIGURATION   string = "24.2"
)
