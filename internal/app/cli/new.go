package cli

import (
	"fmt"
	"strings"

	"struct-framework/internal/app/newproject"
)

func newNewCmd() *Command {
	return &Command{
		Use:   "new",
		Short: "Scaffold a new microservice: struct new <name> [--template=minimal|standard] [--module=path]",
		Run: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("cli: struct new requires a NAME argument")
			}
			name := args[0]

			fs := FlagSet("new")
			template := fs.String("template", "standard", "project template: minimal or standard")
			module := fs.String("module", "", "Go module path for the new project (default: the project name)")
			if err := fs.Parse(args[1:]); err != nil {
				return err
			}

			modulePath := *module
			if modulePath == "" {
				modulePath = name
			}

			if err := newproject.Generate(name, *template, modulePath, projectDisplayName(name)); err != nil {
				return err
			}

			fmt.Printf("scaffolded %s (template=%s, module=%s)\n", name, *template, modulePath)
			fmt.Printf("next: cd %s && go build ./...\n", name)
			return nil
		},
	}
}

func projectDisplayName(name string) string {
	base := name
	if idx := strings.LastIndex(name, "/"); idx != -1 {
		base = name[idx+1:]
	}
	return base
}
