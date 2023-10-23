package ocikms

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"unsafe"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
	"gocloud.dev/gcerrors"
	"gocloud.dev/secrets"
)

func OpenKeeper(ctx context.Context, endpoint, keyid, algo string) (*secrets.Keeper, error) {
	fmt.Println(endpoint, keyid, algo)
	passwd := os.Getenv("OCI_PRIVATE_KEY_PASSWORD")
	providers := []common.ConfigurationProvider{
		common.ConfigurationProviderEnvironmentVariables("oci", passwd),
		// oci sdk uses lower case for reading environment variables, follow them.
	}
	if configFile := os.Getenv("OCI_CONFIG_FILE"); configFile != "" {
		if p, err := common.ConfigurationProviderFromFile(configFile, passwd); err == nil {
			providers = append(providers, p)
		}
	}
	defaultConfig, _ := common.ComposingConfigurationProvider(providers)

	kmsClient, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(defaultConfig, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to init crypto client: %v", err)
	}
	alg, ok := keymanagement.GetMappingEncryptDataDetailsEncryptionAlgorithmEnum(algo)
	if !ok {
		return nil, fmt.Errorf("invalid algo:" + algo)
	}
	return secrets.NewKeeper(&keeper{
		client: kmsClient, keyid: keyid, algo: alg,
	}), nil
}

type keeper struct {
	client keymanagement.KmsCryptoClient
	keyid  string
	algo   keymanagement.EncryptDataDetailsEncryptionAlgorithmEnum
}

// Close implements driver.Keeper.
func (*keeper) Close() error {
	panic("unimplemented")
}

// Decrypt implements driver.Keeper.
func (*keeper) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	panic("unimplemented")
}

// Encrypt implements driver.Keeper.
func (k *keeper) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	encryptReq := keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:               &k.keyid,
			Plaintext:           (*string)(unsafe.Pointer(&plaintext)),
			EncryptionAlgorithm: k.algo,
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
