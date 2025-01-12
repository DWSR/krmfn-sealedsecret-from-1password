package krmfnsealedsecretfrom1password

import (
	"github.com/spf13/cobra"
	"sigs.k8s.io/kustomize/kyaml/fn/framework/command"
)

// NewCmd creates a new command for the processor.
func NewCmd(opts ...ProcessorOption) *cobra.Command {
	return command.Build(NewProcessor(opts...), command.StandaloneEnabled, false)
}
