package krmfnsealedsecretfrom1password_test

import (
	"testing"

	"github.com/1password/onepassword-sdk-go"
	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/testhelpers"
	"github.com/spf13/cobra"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/frameworktestutil"
)

func Test_Cmd(t *testing.T) {
	mockClient := &onepassword.Client{
		Secrets: testhelpers.NewMockResolver(
			map[string]string{
				"op://Vault Name/item/field": "anencryptedvalueofsecret",
			},
		),
	}

	crc := frameworktestutil.CommandResultsChecker{
		TestDataDirectory: "testdata/cmd",
		Command: func() *cobra.Command {
			return krmfnsealedsecretfrom1password.NewCmd(
				krmfnsealedsecretfrom1password.WithClient(mockClient),
				krmfnsealedsecretfrom1password.WithRandSrc(testhelpers.NewStaticReader()),
			)
		},
	}

	crc.Assert(t)
}
