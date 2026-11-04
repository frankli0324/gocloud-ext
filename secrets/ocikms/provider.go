package ocikms

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

func newGCConfigurationProvider(u *url.URL) (common.ConfigurationProvider, error) {
	switch os.Getenv("OCI_CLI_AUTH") {
	case "instance_principal":
		return auth.InstancePrincipalConfigurationProvider()
	case "", "api_key":
	default:
		return nil, fmt.Errorf("unsupported OCI_CLI_AUTH; expected api_key or instance_principal")
	}
	file := os.Getenv("OCI_CLI_CONFIG_FILE")
	if file == "" {
		file = os.Getenv("OCI_CONFIG_FILE")
	}
	profile := os.Getenv("OCI_CLI_PROFILE")
	if u != nil {
		if declared := u.Query().Get("conffile"); declared != "" {
			file = declared
		}
		if declared := u.Query().Get("profile"); declared != "" {
			profile = declared
		}
	}
	if file == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		file = filepath.Join(home, ".oci", "config")
	}
	if profile == "" {
		profile = "DEFAULT"
	}
	return common.ConfigurationProviderFromFileWithProfile(file, profile, os.Getenv("OCI_PRIVATE_KEY_PASSWORD"))
}
