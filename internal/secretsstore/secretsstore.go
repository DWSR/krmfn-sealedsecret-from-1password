// The secretsstore package contains an interface and wrapper around the onepassword-sdk-go Client. The purpose
// of this is to facilitate testing.
package secretsstore

import (
	"context"
	"errors"

	"github.com/1password/onepassword-sdk-go"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/version"
)

type (
	// SecretsStore is a wrapper interface for the onepassword client. Its primary purpose is to enable
	// mocking out the 1Password client for testing purposes.
	SecretsStore interface {
		Resolve(ctx context.Context, secretReference string) (string, error)
	}

	// OnePasswordStore is a wrapper around the 1Password client that implements the SecretsStore interface.
	OnePasswordStore struct {
		client *onepassword.Client
	}
)

const (
	integrationName = "SealedSecret from 1Password KRM Function"
)

var (
	// ErrOnePasswordStoreCreation is returned when a 1Password client is unable to be created.
	ErrOnePasswordStoreCreation = errors.New("unable to create 1Password client")

	// ErrSecretsStoreResolve is returned when a secret reference cannot be resolved.
	ErrSecretsStoreResolve = errors.New("unable to resolve secret")
)

// Resolve resolves the secret reference using the 1Password client.
func (o *OnePasswordStore) Resolve(ctx context.Context, reference string) (string, error) {
	secret, err := o.client.Secrets().Resolve(ctx, reference)
	if err != nil {
		return "", errors.Join(ErrSecretsStoreResolve, err)
	}

	return secret, nil
}

// NewOnePasswordStore creates a new OnePasswordStore with the provided service account token.
func NewOnePasswordStore(ctx context.Context, tok string) (*OnePasswordStore, error) {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(tok),
		onepassword.WithIntegrationInfo(integrationName, version.Version()),
	)
	if err != nil {
		return nil, errors.Join(ErrOnePasswordStoreCreation, err)
	}

	return &OnePasswordStore{client}, nil
}
