package version

// TSM is changed in the release jobs on gitlab and contains the tag of the release.
const TSM string = "69.0.0"

// These values are also changed in the release jobs and contain the version number of the corresponding component.
const (
	CLIENT_COMMUNICATION string = "29.1"
	CLIENT_API           string = "59.0"
	NODE_COMMUNICATION   string = "32.1"
	NODE_CONFIGURATION   string = "21.4"
)
