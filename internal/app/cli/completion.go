package cli

import "fmt"

// newCompletionCmd generates a shell completion script listing the
// top-level command surface. It is intentionally static (not dynamically
// walking subcommand flags) — the hand-rolled command tree in command.go
// has no flag-introspection API yet; extend this alongside a real cobra
// swap (see command.go's doc comment) rather than building that
// introspection twice.
func newCompletionCmd() *Command {
	return &Command{
		Use:   "completion",
		Short: "Generate a shell completion script: struct completion bash|zsh|fish",
		Run: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("cli: struct completion requires a shell argument (bash, zsh, or fish)")
			}
			switch args[0] {
			case "bash":
				fmt.Print(bashCompletion)
			case "zsh":
				fmt.Print(zshCompletion)
			case "fish":
				fmt.Print(fishCompletion)
			default:
				return fmt.Errorf("cli: unsupported shell %q (want bash, zsh, or fish)", args[0])
			}
			return nil
		},
	}
}

const topLevelCommands = "new workspace doctor serve migrate seed make routes lint bench health version about db completion"

const bashCompletion = `# struct bash completion — install with:
#   source <(struct completion bash)
_struct_completions() {
  local cur="${COMP_WORDS[COMP_CWORD]}"
  COMPREPLY=($(compgen -W "` + topLevelCommands + `" -- "$cur"))
}
complete -F _struct_completions struct
`

const zshCompletion = `#compdef struct
# struct zsh completion — install with:
#   struct completion zsh > "${fpath[1]}/_struct"
_struct() {
  _arguments '1: :(` + topLevelCommands + `)'
}
_struct
`

const fishCompletion = `# struct fish completion — install with:
#   struct completion fish > ~/.config/fish/completions/struct.fish
complete -c struct -f -a "` + topLevelCommands + `"
`
