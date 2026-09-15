// Package codegen backs every `struct make ...` command (framework guide
// §10.1). It never overwrites an existing file, and every generated file
// is passed through go/format.Source before being written, so a scaffold
// command that would produce invalid Go fails loudly instead of leaving
// broken code on disk.
package codegen

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ModulePath reads the `module` directive from ./go.mod so generated files
// use the correct import path regardless of which project `struct` is run
// inside — it must never be hardcoded to this framework's own module name.
func ModulePath() (string, error) {
	f, err := os.Open("go.mod")
	if err != nil {
		return "", fmt.Errorf("codegen: could not read go.mod in the current directory: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module")), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("codegen: reading go.mod: %w", err)
	}
	return "", fmt.Errorf("codegen: no module directive found in go.mod")
}
