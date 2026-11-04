//go:build ociintegration

package ocikms_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	_ "github.com/frankli0324/gocloud-ext/secrets/ocikms"
	"github.com/oracle/oci-go-sdk/v65/common"
	"gocloud.dev/gcerrors"
	"gocloud.dev/secrets"
)

func TestOCIRealKeeper(t *testing.T) {
	uri := os.Getenv("OCIKMS_TEST_URL")
	if uri == "" {
		t.Fatal("OCIKMS_TEST_URL must select an existing OCI Key Management key")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	k, err := secrets.OpenKeeper(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	data := make([]byte, 32)
	if _, err = rand.Read(data); err != nil {
		t.Fatal(err)
	}
	cipher, err := k.Encrypt(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	second, err := k.Encrypt(ctx, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(cipher) == 0 || bytes.Equal(cipher, data) || bytes.Equal(cipher, second) {
		t.Fatal("encryption did not produce distinct ciphertext")
	}
	reopened, err := secrets.OpenKeeper(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	actual, err := reopened.Decrypt(ctx, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, actual) {
		t.Fatal("binary round trip failed after reopening")
	}
	_, bad := k.Decrypt(ctx, []byte("invalid-ciphertext"))
	if bad == nil || gcerrors.Code(bad) != gcerrors.InvalidArgument {
		t.Fatalf("wanted native invalid argument error, got %v", bad)
	}
	var native common.ServiceError
	if !k.ErrorAs(bad, &native) || native.GetHTTPStatusCode() != 400 {
		t.Fatal("native OCI error was not exposed")
	}
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err = k.Encrypt(canceled, data); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not propagated")
	}
}
