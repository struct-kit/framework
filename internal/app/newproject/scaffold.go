package newproject

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
)

var validTemplates = map[string]bool{"minimal": true, "standard": true}

// Generate scaffolds a new project at targetDir from the named template,
// rewriting every occurrence of the template's module-path placeholder to
// modulePath and every occurrence of the project-name placeholder to
// projectName. It refuses to run if targetDir already exists — scaffolding
// into an existing directory is exactly the kind of silent overwrite the
// framework guide's codegen commands are built to avoid (§10).
func Generate(targetDir, templateName, modulePath, projectName string) error {
	if !validTemplates[templateName] {
		return fmt.Errorf("newproject: unknown template %q (want \"minimal\" or \"standard\")", templateName)
	}
	if _, err := os.Stat(targetDir); err == nil {
		return fmt.Errorf("newproject: %s already exists — refusing to scaffold into it", targetDir)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("newproject: checking %s: %w", targetDir, err)
	}

	root := path.Join("template", templateName)

	err := fs.WalkDir(Templates, root, func(embeddedPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, embeddedPath)
		if err != nil {
			return fmt.Errorf("newproject: computing relative path for %s: %w", embeddedPath, err)
		}
		rel = renameTemplateFile(rel)

		content, err := Templates.ReadFile(embeddedPath)
		if err != nil {
			return fmt.Errorf("newproject: reading embedded %s: %w", embeddedPath, err)
		}
		content = applyPlaceholders(content, modulePath, projectName)

		destPath := filepath.Join(targetDir, rel)
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			return fmt.Errorf("newproject: creating %s: %w", filepath.Dir(destPath), err)
		}
		if err := os.WriteFile(destPath, content, 0o644); err != nil {
			return fmt.Errorf("newproject: writing %s: %w", destPath, err)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// git init is best-effort: a project scaffolded in an environment
	// without git installed is still a complete, usable project.
	cmd := exec.Command("git", "init", targetDir)
	_ = cmd.Run()

	return nil
}

// renameTemplateFile maps the embedded template's on-disk names back to
// what a real project needs. Every template file ends in ".tmpl" — for
// two reasons: go:embed excludes dotfiles by default (so ".gitignore"
// can't be embedded directly), and, more importantly, a bare ".go" file
// living under this template tree would be picked up by this very
// module's own `go build ./...`/`go vet ./...` as a real package — one
// that imports the unresolvable literal path "__MODULE_PLACEHOLDER__/...".
// The ".tmpl" suffix keeps every template file inert to the framework's
// own build until Generate rewrites it here.
func renameTemplateFile(rel string) string {
	base := filepath.Base(rel)
	dir := filepath.Dir(rel)

	base = strings.TrimSuffix(base, ".tmpl")
	if base == "gitignore" {
		base = ".gitignore"
	}

	if dir == "." {
		return base
	}
	return filepath.Join(dir, base)
}

func applyPlaceholders(content []byte, modulePath, projectName string) []byte {
	s := string(content)
	s = strings.ReplaceAll(s, "__MODULE_PLACEHOLDER__", modulePath)
	s = strings.ReplaceAll(s, "{{ProjectName}}", projectName)
	return []byte(s)
}
