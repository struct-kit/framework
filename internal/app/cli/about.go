package cli

import "fmt"

func newAboutCmd() *Command {
	return &Command{
		Use:   "about",
		Short: "Print information about the framework",
		Run: func(args []string) error {
			fmt.Println(`Struct — a typed-first, secure, high-performance Go microservice framework.
MVC architecture, driver-agnostic PostgreSQL/MySQL store layer, built-in
i18n, and a first-party CLI. See STRUCT_FRAMEWORK.md for the full guide.`)
			return nil
		},
	}
}
