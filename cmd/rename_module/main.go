package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	dirs := []string{"cmd", "internal", "tests"}
	var count int

	for _, d := range dirs {
		_ = filepath.Walk(d, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			content, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			orig := content
			content = bytes.ReplaceAll(content, []byte("\"struct-framework/"), []byte("\"struct/"))
			content = bytes.ReplaceAll(content, []byte("\"struct-service/"), []byte("\"struct/"))
			content = bytes.ReplaceAll(content, []byte("struct-service"), []byte("struct"))
			content = bytes.ReplaceAll(content, []byte("struct-framework"), []byte("struct"))

			if !bytes.Equal(orig, content) {
				if err := os.WriteFile(path, content, info.Mode()); err == nil {
					count++
				}
			}
			return nil
		})
	}

	// Also update Makefile
	if content, err := os.ReadFile("Makefile"); err == nil {
		content = bytes.ReplaceAll(content, []byte("struct-service/"), []byte("struct/"))
		content = bytes.ReplaceAll(content, []byte("struct-framework/"), []byte("struct/"))
		_ = os.WriteFile("Makefile", content, 0644)
	}

	fmt.Printf("Successfully updated module paths in %d files\n", count)
}
