package main

import (
	"fmt"
	"os"

	"struct-framework/internal/app/cli"
)

func main() {
	root := cli.NewRootCommand()
	if err := root.Execute(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
