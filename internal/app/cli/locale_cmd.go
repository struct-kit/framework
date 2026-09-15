package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"struct-framework/internal/app/codegen"
)

// localesDir and sourceLocale match internal/platform/i18n's embedded
// layout exactly — see that package's doc comment for why locales/ lives
// there rather than at the project root.
const (
	localesDir   = "internal/platform/i18n/locales"
	sourceLocale = "en"
)

func newMakeLocaleCmd() *Command {
	return &Command{
		Use:   "locale",
		Short: "Scaffold a new locale catalog: struct make locale LANG",
		Run: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("cli: struct make locale requires a LANG argument (e.g. \"fr\")")
			}
			return makeLocaleFile(args[0])
		},
	}
}

func makeLocaleFile(lang string) error {
	sourcePath := fmt.Sprintf("%s/%s.json", localesDir, sourceLocale)
	sourceBytes, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("cli: reading source locale %s: %w", sourcePath, err)
	}

	var sourceKeys map[string]string
	if err := json.Unmarshal(sourceBytes, &sourceKeys); err != nil {
		return fmt.Errorf("cli: parsing source locale %s: %w", sourcePath, err)
	}

	stub := make(map[string]string, len(sourceKeys))
	for k := range sourceKeys {
		stub[k] = "" // every value starts empty, flagged for translation below
	}
	stubJSON, err := json.MarshalIndent(stub, "", "  ")
	if err != nil {
		return fmt.Errorf("cli: encoding new locale catalog: %w", err)
	}

	destPath := fmt.Sprintf("%s/%s.json", localesDir, lang)
	if err := codegen.WriteFile(destPath, string(stubJSON)+"\n"); err != nil {
		return err
	}

	fmt.Println("created", destPath)
	fmt.Printf("%d key(s) need translation — every value is currently empty\n", len(stub))
	fmt.Println("add", fmt.Sprintf("%q", lang), "to SUPPORTED_LOCALES once translated, or `struct doctor` will")
	fmt.Println("flag it as incomplete if you enable it before filling every key in")
	return nil
}
