// Package newproject implements `struct new` (framework guide §10.3):
// scaffolding a fresh microservice from an embedded template.
package newproject

import "embed"

//go:embed template/minimal template/standard
var Templates embed.FS
