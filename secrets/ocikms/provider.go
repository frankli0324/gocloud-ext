package ocikms

import (
	"crypto/rsa"
	"fmt"
	"net/url"
	"os"

	"github.com/oracle/oci-go-sdk/v65/common"
)

var _ common.ConfigurationProvider = urlConfigurationProvider{}

func newGCConfigurationProvider(u *url.URL) common.ConfigurationProvider {
	passwd := os.Getenv("OCI_PRIVATE_KEY_PASSWORD")
	providers := []common.ConfigurationProvider{}

	if configFile := os.Getenv("OCI_CONFIG_FILE"); configFile != "" {
		if p, err := common.ConfigurationProviderFromFile(configFile, passwd); err == nil {
			providers = append(providers, p)
		}
	}
	if u != nil {
		query := u.Query()
		if f := query.Get("conffile"); f != "" {
			if p, err := common.ConfigurationProviderFromFile(f, passwd); err == nil {
				providers = append(providers, p)
			}
		}
		providers = append(providers, urlConfigurationProvider{query})
	}
	providers = append(providers, common.DefaultConfigProvider())
	provider, _ := common.ComposingConfigurationProvider(providers)
	return provider
}

type urlConfigurationProvider struct {
	q url.Values
}

// PrivateRSAKey implements common.ConfigurationProvider.
func (urlConfigurationProvider) PrivateRSAKey() (*rsa.PrivateKey, error) {
	return nil, fmt.Errorf("unsupported, keep the interface")
}

// AuthType implements common.ConfigurationProvider.
func (u urlConfigurationProvider) AuthType() (common.AuthConfig, error) {
	return common.AuthConfig{
		AuthType: common.UnknownAuthenticationType, IsFromConfigFile: false, OboToken: nil,
	}, fmt.Errorf("unsupported, keep the interface")
}

func shouldGetQuery(v url.Values, k string) (string, error) {
	vv := v.Get(k)
	if vv == "" {
		return "", fmt.Errorf("not found" + k)
	}
	return vv, nil
}

// KeyID implements common.ConfigurationProvider.
func (p urlConfigurationProvider) KeyID() (keyID string, err error) {
	tenancy, err := p.TenancyOCID()
	if err != nil {
		return
	}

	user, err := p.UserOCID()
	if err != nil {
		return
	}

	fingerprint, err := p.KeyFingerprint()
	if err != nil {
		return
	}

	return fmt.Sprintf("%s/%s/%s", tenancy, user, fingerprint), nil
}

// KeyFingerprint implements common.ConfigurationProvider.
func (u urlConfigurationProvider) KeyFingerprint() (string, error) {
	return shouldGetQuery(u.q, "fingerprint")
}

// Region implements common.ConfigurationProvider.
func (u urlConfigurationProvider) Region() (string, error) {
	return shouldGetQuery(u.q, "region")
}

// TenancyOCID implements common.ConfigurationProvider.
func (u urlConfigurationProvider) TenancyOCID() (string, error) {
	return shouldGetQuery(u.q, "tenancy")
}

// UserOCID implements common.ConfigurationProvider.
func (u urlConfigurationProvider) UserOCID() (string, error) {
	return shouldGetQuery(u.q, "user")
}
