package krmfnsealedsecretfrom1password_test

import (
	"os"
	"path/filepath"
	"testing"

	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/testhelpers"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/frameworktestutil"
)

func Test_Cmd(t *testing.T) {
	mockStore := testhelpers.NewMockSecretsStore(
		map[string]string{
			"op://Vault Name/item/field": "anencryptedvalueofsecret",
		},
	)

	crc := frameworktestutil.CommandResultsChecker{
		TestDataDirectory: "testdata/cmd",
		Command: func() *cobra.Command {
			return krmfnsealedsecretfrom1password.NewCmd(
				krmfnsealedsecretfrom1password.WithSecretsStore(mockStore),
				krmfnsealedsecretfrom1password.WithRandSrc(testhelpers.NewStaticReader()),
			)
		},
	}

	crc.Assert(t)
}

func Test_Cmd_LoadTokenFromFile(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "token")
	err := os.WriteFile(tokenFile, []byte("token"), 0o600)
	require.NoError(t, err)

	crc := frameworktestutil.CommandResultsChecker{
		TestDataDirectory: "testdata/cmd-token-file",
		Command: func() *cobra.Command {
			return krmfnsealedsecretfrom1password.NewCmd(
				krmfnsealedsecretfrom1password.WithOnePasswordServiceAccountTokenFile(tokenFile),
			)
		},
	}

	crc.Assert(t)
}

func Test_Cmd_LoadTokenFromEnv(t *testing.T) {
	t.Setenv("OP_SERVICE_ACCOUNT_TOKEN", "token")

	crc := frameworktestutil.CommandResultsChecker{
		TestDataDirectory: "testdata/cmd-token-env",
		Command: func() *cobra.Command {
			return krmfnsealedsecretfrom1password.NewCmd()
		},
	}

	crc.Assert(t)
}
