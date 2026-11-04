//go:build ociintegration

package ocikms_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	"gocloud.dev/gcerrors"
	"gocloud.dev/secrets"
	"gocloud.dev/secrets/driver"
	"gocloud.dev/secrets/drivertest"
)

type publicDriver struct{ *secrets.Keeper }

func (publicDriver) ErrorCode(err error) gcerrors.ErrorCode { return gcerrors.Code(err) }

type realHarness struct{ urls [2]string }

func (h realHarness) Close() {}
func (h realHarness) MakeDriver(ctx context.Context) (driver.Keeper, driver.Keeper, error) {
	first, err := secrets.OpenKeeper(ctx, h.urls[0])
	if err != nil {
		return nil, nil, err
	}
	second, err := secrets.OpenKeeper(ctx, h.urls[1])
	if err != nil {
		first.Close()
		return nil, nil, err
	}
	return publicDriver{first}, publicDriver{second}, nil
}

func TestOCIConformance(t *testing.T) {
	drivertest.RunConformanceTests(t, func(ctx context.Context, t *testing.T) (drivertest.Harness, error) {
		urls := [2]string{os.Getenv("OCIKMS_TEST_URL"), os.Getenv("OCIKMS_SECOND_TEST_URL")}
		if urls[0] == "" || urls[1] == "" || urls[0] == urls[1] {
			return nil, fmt.Errorf("two distinct authorized OCI test key URLs are required")
		}
		return realHarness{urls: urls}, nil
	}, nil)
}
