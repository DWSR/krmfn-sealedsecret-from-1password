package krmfnsealedsecretfrom1password

import (
	"context"
	"errors"
	"regexp"

	"github.com/1password/onepassword-sdk-go"
)

// SecretReference is a reference to a secret in 1Password.
type SecretReference struct {
	vaultName  string
	vaultItem  string
	vaultField string
}

var (
	// ErrInvalidSecretReference is returned when the secret reference is invalid.
	ErrInvalidSecretReference = errors.New("invalid secret reference")

	secretReferencePattern = regexp.MustCompile(`^op://(?P<VaultName>[^/]+)/(?P<VaultItem>[^/]+)/(?P<VaultField>.+)$`)
)

func (r *SecretReference) String() string {
	return "op://" + r.vaultName + "/" + r.vaultItem + "/" + r.vaultField
}

// VaultName returns the name of the vault that the referenced secret resides in.
func (r *SecretReference) VaultName() string {
	return r.vaultName
}

// VaultItem returns the path to the referenced secret in the vault.
func (r *SecretReference) VaultItem() string {
	return r.vaultItem
}

// VaultField returns the field of the referenced secret.
func (r *SecretReference) VaultField() string {
	return r.vaultField
}

// SecretReferenceFromString creates a SecretReference from a string. It will return an ErrInvalidSecretReference
// if the string is not a well-formed secre reference. It does not check that the secret exists.
func SecretReferenceFromString(ctx context.Context, refStr string) (*SecretReference, error) {
	if err := onepassword.Secrets.ValidateSecretReference(ctx, refStr); err != nil {
		return nil, errors.Join(ErrInvalidSecretReference, err)
	}

	matches := secretReferencePattern.FindStringSubmatch(refStr)

	if matches == nil {
		return nil, ErrInvalidSecretReference
	}

	return &SecretReference{
		vaultName:  matches[1],
		vaultItem:  matches[2],
		vaultField: matches[3],
	}, nil
}
