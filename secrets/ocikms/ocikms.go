// package ocikms implements gocloud.dev secrets interface for oci
package ocikms

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"gocloud.dev/secrets"
)

const Scheme = "ocikms"

func init() {
	secrets.DefaultURLMux().RegisterKeeper(Scheme, new(URLOpener))
}

type URLOpener struct{}

func (o *URLOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*secrets.Keeper, error) {
	if u.Scheme != Scheme || u.Host == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.TrimPrefix(u.Path, "/") == "" {
		return nil, errors.New("ocikms URL requires a crypto endpoint and key reference without credentials")
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, errors.New("invalid ocikms URL query")
	}
	for name, values := range query {
		if name != "algo" && name != "conffile" && name != "profile" {
			return nil, errors.New("unsupported ocikms URL query parameter")
		}
		if len(values) != 1 || values[0] == "" {
			return nil, errors.New("ocikms URL parameters require one nonempty value")
		}
	}
	algo := query.Get("algo")
	if algo == "" {
		algo = "AES_256_GCM"
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider, err := newGCConfigurationProvider(u)
	if err != nil {
		return nil, err
	}
	return OpenKeeper(ctx, "https://"+u.Host, strings.TrimPrefix(u.Path, "/"), algo, provider)
}
