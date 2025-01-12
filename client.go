package krmfnsealedsecretfrom1password

import (
	"context"
	"errors"

	"github.com/1password/onepassword-sdk-go"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/version"
)

const (
	integrationName = "SealedSecret from 1Password KRM Function"
)

// ErrClientCreation is returned when a 1Password client is unable to be created.
var ErrClientCreation = errors.New("unable to create 1Password client")

// NewClient creates a new 1Password client with the provided service account token.
func NewClient(ctx context.Context, tok string) (*onepassword.Client, error) {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(tok),
		onepassword.WithIntegrationInfo(integrationName, version.Version()),
	)
	if err != nil {
		return nil, errors.Join(ErrClientCreation, err)
	}

	return client, nil
}
