// package ocikms implements gocloud.dev secrets interface for oci
package ocikms

import (
	"gocloud.dev/secrets"
)

const Scheme = "ocikms"

func init() {
	secrets.DefaultURLMux().RegisterKeeper(Scheme, new(URLOpener))
}
