package krmfnsealedsecretfrom1password_test

import (
	"context"
	"testing"

	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_SecretReferenceFromString(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		Name       string
		SrcString  string
		VaultName  string
		VaultItem  string
		VaultField string
		ExpectErr  bool
	}{
		{
			Name:       "WellFormed",
			SrcString:  "op://vault/item/field",
			VaultName:  "vault",
			VaultItem:  "item",
			VaultField: "field",
			ExpectErr:  false,
		},
		{
			Name:       "SpaceinVaultName",
			SrcString:  "op://Vault With Space/item/section/field",
			VaultName:  "Vault With Space",
			VaultItem:  "item",
			VaultField: "section/field",
			ExpectErr:  false,
		},
		{
			Name:      "NoItem",
			SrcString: "op://vault",
			ExpectErr: true,
		},
		{
			Name:      "NoField",
			SrcString: "op://vault/item",
			ExpectErr: true,
		},
		{
			Name:      "WrongScheme",
			SrcString: "http://vault/path/to/item",
			ExpectErr: true,
		},
	}

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			ref, err := krmfnsealedsecretfrom1password.SecretReferenceFromString(ctx, tc.SrcString)
			if tc.ExpectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.VaultName, ref.VaultName())
				assert.Equal(t, tc.VaultItem, ref.VaultItem())
				assert.Equal(t, tc.VaultField, ref.VaultField())
			}
		})
	}
}
