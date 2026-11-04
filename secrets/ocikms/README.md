# OCI Key Management driver for Go Cloud Secrets

This driver implements the existing Go Cloud Secrets `driver.Keeper` interface
using Oracle's official Go SDK. It encrypts and decrypts arbitrary plaintext
bytes, including binary data keys. Ciphertext is the opaque encoded value
returned by OCI; no additional envelope or crypto format is introduced.

```text
ocikms://<crypto-endpoint>/<key-ocid>
```

The crypto endpoint must use HTTPS. Credentials and fragments are rejected.
The optional query parameters are `algo`, `conffile` and `profile`. Each must
have exactly one nonempty value. `algo` defaults to `AES_256_GCM`; supported
algorithm names are normalized using the OCI SDK's enum mapping.

## Authentication

`OpenKeeper` accepts an explicit OCI `common.ConfigurationProvider`. The URL
opener resolves one provider using the following inputs:

- `OCI_CLI_AUTH=instance_principal` selects the native OCI instance principal
  provider. File/profile settings do not apply to that authentication mode.
- `OCI_CLI_AUTH=api_key`, or an absent selector, uses one configuration file
  and profile. Authentication failures do not trigger another provider.
- The `conffile` query reference overrides `OCI_CLI_CONFIG_FILE`, then
  `OCI_CONFIG_FILE`; otherwise the standard `~/.oci/config` path is used.
- The `profile` query reference overrides `OCI_CLI_PROFILE`; otherwise the
  standard `DEFAULT` profile is used.
- `OCI_PRIVATE_KEY_PASSWORD` remains supported for encrypted API keys.

Keep credentials out of URLs and logs. Prefer environment/configuration
references that can differ between executors instead of embedding a
host-specific file reference in a persisted secrets-provider URL.

Grant the executor the OCI permissions to encrypt and decrypt using the
selected key. This driver does not create keys or grant permissions. It is
independent of Object Storage and does not require storage credentials.

## Verification

Run formatting, static checks and offline input-validation regressions:

```sh
gofmt -w secrets/ocikms/*.go
go vet ./...
go test -count=1 ./...
```

Run the actual OCI integration test with an existing authorized test key:

```sh
OCIKMS_TEST_URL='ocikms://<crypto-endpoint>/<key-ocid>' \
  go test -count=1 -tags ociintegration ./secrets/ocikms
```

The integration test fails if its key reference is absent; it does not skip
or substitute a simulated service. It checks binary data keys, randomized
ciphertexts, reopening, native service errors and cancellation. Fresh-process,
instance-principal and Pulumi migration acceptance must also be recorded by
the consuming project before production adoption.

## Behavior corrected from the initial prototype

OCI requires plaintext to be Base64-encoded on encryption and returns
Base64-encoded plaintext on decryption. The initial driver forwarded raw
bytes as strings and was not correct for arbitrary binary data keys. It
also panicked in `ErrorAs` and classified all failures as unimplemented.
These are corrected at the driver boundary. Clients relying on the old
Base64-string-only behavior must validate their migration explicitly.
