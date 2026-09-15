// Package cli implements the struct command surface (framework guide §10).
//
// Deviation from the framework guide: §10.2 originally specified
// spf13/cobra. This build environment has no network access to the Go
// module proxy, so this is a small hand-rolled command tree with a
// cobra-shaped API (Use/Short/Run, AddCommand, Execute) — swap for real
// cobra as soon as module fetching is available; call sites in root.go
// would need no changes beyond the import.
package cli

import (
	"flag"
	"fmt"
)

type Command struct {
	Use   string
	Short string
	Run   func(args []string) error

	subcommands map[string]*Command
}

func (c *Command) AddCommand(children ...*Command) {
	if c.subcommands == nil {
		c.subcommands = make(map[string]*Command)
	}
	for _, child := range children {
		c.subcommands[child.Use] = child
	}
}

// Execute dispatches os.Args[1:] (passed via Run's args parameter at the
// root) down the command tree. A command with no Run and no matching
// subcommand prints help and returns nil.
func (c *Command) Execute(args []string) error {
	if len(args) == 0 {
		if c.Run != nil {
			return c.Run(nil)
		}
		c.printHelp()
		return nil
	}

	if child, ok := c.subcommands[args[0]]; ok {
		return child.Execute(args[1:])
	}

	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		c.printHelp()
		return nil
	}

	if c.Run != nil {
		return c.Run(args)
	}

	return fmt.Errorf("unknown command %q for %q — run `%s help`", args[0], c.Use, c.Use)
}

func (c *Command) printHelp() {
	fmt.Printf("%s — %s\n\n", c.Use, c.Short)
	if len(c.subcommands) > 0 {
		fmt.Println("Available commands:")
		for _, sub := range c.subcommands {
			fmt.Printf("  %-20s %s\n", sub.Use, sub.Short)
		}
	}
}

// FlagSet is a small convenience constructor so subcommands can declare
// their own flags without importing "flag" directly at every call site.
func FlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
