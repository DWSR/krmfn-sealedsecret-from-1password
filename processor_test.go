package krmfnsealedsecretfrom1password_test

import (
	"testing"

	krmfnsealedsecretfrom1password "github.com/DWSR/krmfn-sealedsecret-from-1password"
	"github.com/DWSR/krmfn-sealedsecret-from-1password/internal/testhelpers"
	"sigs.k8s.io/kustomize/kyaml/fn/framework"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/frameworktestutil"
)

func Test_Process(t *testing.T) {
	mockStore := testhelpers.NewMockSecretsStore(
		map[string]string{
			"op://Vault Name/item/field": "anencryptedvalueofsecret",
		},
	)

	prc := frameworktestutil.ProcessorResultsChecker{
		TestDataDirectory: "testdata/processor",
		Processor: func() framework.ResourceListProcessor {
			return krmfnsealedsecretfrom1password.NewProcessor(
				krmfnsealedsecretfrom1password.WithSecretsStore(mockStore),
				krmfnsealedsecretfrom1password.WithRandSrc(testhelpers.NewStaticReader()),
			)
		},
	}

	prc.Assert(t)
}
