package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newCompletionCmd() *cobra.Command {
	return &cobra.Command{
		Use:       "completion [bash|zsh|fish]",
		Short:     "Generate shell completion scripts",
		Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
		ValidArgs: []string{"bash", "zsh", "fish"},
		Long: `Generate shell completion scripts for varax.

Bash:
  $ varax completion bash > /etc/bash_completion.d/varax
  # or
  $ source <(varax completion bash)

Zsh:
  $ varax completion zsh > "${fpath[1]}/_varax"
  # or
  $ source <(varax completion zsh)

Fish:
  $ varax completion fish > ~/.config/fish/completions/varax.fish
  # or
  $ varax completion fish | source`,
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}
