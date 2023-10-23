package ocikms

import (
	"context"
	"fmt"
	"reflect"
	"unsafe"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"gocloud.dev/gcerrors"
	"gocloud.dev/secrets"
)

func OpenKeeper(
	ctx context.Context,
	endpoint, keyid, algo string,
	configProvider common.ConfigurationProvider,
) (*secrets.Keeper, error) {
	if configProvider == nil {
		configProvider = newGCConfigurationProvider(nil)
	}

	kmsClient, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(configProvider, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to init crypto client: %v", err)
	}
	_, ok := keymanagement.GetMappingEncryptDataDetailsEncryptionAlgorithmEnum(algo)
	if !ok {
		return nil, fmt.Errorf("invalid algo:" + algo)
	}
	return secrets.NewKeeper(&keeper{
		client: kmsClient, keyid: keyid, algo: algo,
	}), nil
}

type keeper struct {
	client keymanagement.KmsCryptoClient
	keyid  string
	algo   string
}

// Close implements driver.Keeper.
func (k *keeper) Close() error { return nil }

// Decrypt implements driver.Keeper.
func (k *keeper) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	req := keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			KeyId:               &k.keyid,
			Ciphertext:          (*string)(unsafe.Pointer(&ciphertext)),
			EncryptionAlgorithm: keymanagement.DecryptDataDetailsEncryptionAlgorithmEnum(k.algo),
		},
	}
	resp, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return fromStringPtr(resp.Plaintext), nil
}

// Encrypt implements driver.Keeper.
func (k *keeper) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	encryptReq := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:               &k.keyid,
			Plaintext:           (*string)(unsafe.Pointer(&plaintext)),
			EncryptionAlgorithm: keymanagement.EncryptDataDetailsEncryptionAlgorithmEnum(k.algo),
		},
	}
	resp, err := k.client.Encrypt(ctx, encryptReq)
	if err != nil {
		return nil, err
	}
	return fromStringPtr(resp.Ciphertext), nil
}

// ErrorAs implements driver.Keeper.
func (*keeper) ErrorAs(err error, i interface{}) bool {
	panic("unimplemented")
}

// ErrorCode implements driver.Keeper.
func (*keeper) ErrorCode(err error) gcerrors.ErrorCode {
	return gcerrors.Unimplemented
}

func fromStringPtr(s *string) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer((*reflect.StringHeader)(unsafe.Pointer(s)).Data)), len(*s))
}
