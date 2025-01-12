package krmfnsealedsecretfrom1password_test

import (
	"testing"

	"github.com/1password/onepassword-sdk-go"
	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/testhelpers"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/frameworktestutil"
)

func Test_Process(t *testing.T) {
	mockClient := &onepassword.Client{
		Secrets: testhelpers.NewMockResolver(
			map[string]string{
				"op://Vault Name/item/field": "anencryptedvalueofsecret",
			},
		),
	}

	prc := frameworktestutil.ProcessorResultsChecker{
		TestDataDirectory: "testdata/processor",
		Processor: func() framework.ResourceListProcessor {
			return krmfnsealedsecretfrom1password.NewProcessor(
				krmfnsealedsecretfrom1password.WithClient(mockClient),
				krmfnsealedsecretfrom1password.WithRandSrc(testhelpers.NewStaticReader()),
			)
		},
	}

	prc.Assert(t)
}
