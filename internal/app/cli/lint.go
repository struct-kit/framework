package cli

import (
	"fmt"
	"os"
	"os/exec"
)

func newLintCmd() *Command {
	return &Command{
		Use:   "lint",
		Short: "Run gofmt -l, go vet, and golangci-lint (if installed) in one command",
		Run: func(args []string) error {
			failed := false

			if !runCheck("gofmt", "gofmt", "-l", ".") {
				failed = true
			}
			if !runCheck("go vet", "go", "vet", "./...") {
				failed = true
			}
			if _, err := exec.LookPath("golangci-lint"); err == nil {
				if !runCheck("golangci-lint", "golangci-lint", "run", "./...") {
					failed = true
				}
			} else {
				fmt.Println("[skip] golangci-lint not found on PATH")
			}

			if failed {
				return fmt.Errorf("cli: lint failed — see output above")
			}
			fmt.Println("lint passed")
			return nil
		},
	}
}

// runCheck runs name with its args, streaming stdout/stderr straight
// through, and reports whether it succeeded. gofmt -l is a special case:
// it exits 0 even when it lists unformatted files, so any non-empty
// output is also treated as a failure.
func runCheck(name string, command string, args ...string) bool {
	cmd := exec.Command(command, args...)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if len(out) > 0 {
		os.Stdout.Write(out)
	}
	if err != nil {
		fmt.Printf("[FAIL] %s\n", name)
		return false
	}
	if name == "gofmt" && len(out) > 0 {
		fmt.Printf("[FAIL] %s reported unformatted files\n", name)
		return false
	}
	fmt.Printf("[ OK ] %s\n", name)
	return true
}
