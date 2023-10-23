package ocikms

import (
	"context"
	"net/url"

	"gocloud.dev/secrets"
)

type URLOpener struct{}

func (o *URLOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*secrets.Keeper, error) {
	algo := u.Query().Get("algo")
	if algo == "" {
		algo = "aes_256_gcm"
	}
	return OpenKeeper(ctx, u.Host, u.Path[1:], algo)
}
