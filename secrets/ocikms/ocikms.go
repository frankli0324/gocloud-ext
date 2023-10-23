// package ocikms implements gocloud.dev secrets interface for oci
package ocikms

import (
	"context"
	"net/url"

	"gocloud.dev/secrets"
)

const Scheme = "ocikms"

func init() {
	secrets.DefaultURLMux().RegisterKeeper(Scheme, new(URLOpener))
}

type URLOpener struct{}

func (o *URLOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*secrets.Keeper, error) {
	algo := u.Query().Get("algo")
	if algo == "" {
		algo = "aes_256_gcm"
	}
	return OpenKeeper(ctx, u.Host, u.Path[1:], algo, newGCConfigurationProvider(u))
}
