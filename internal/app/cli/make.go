package cli

import (
	"fmt"
	"strings"

	"struct-framework/internal/app/codegen"
)

func newMakeCmd() *Command {
	root := &Command{
		Use:   "make",
		Short: "Scaffold a model, controller, service, dto, repository, resource, enum, policy, event, job, or locale",
	}
	root.AddCommand(
		makeSubcommand("model", "Scaffold a model struct with validation tags", makeModel),
		makeSubcommand("controller", "Scaffold a controller + matching test file", makeController),
		makeSubcommand("service", "Scaffold a service interface + in-memory implementation", makeService),
		makeSubcommand("dto", "Scaffold a request/response DTO under internal/mvc/views", makeDTO),
		makeSubcommand("repository", "Scaffold a repository for both Postgres and MySQL", makeRepository),
		makeSubcommand("resource", "Scaffold full MVC + repository stack (model, DTO, service, repositories, controller)", makeResource),
		makeSubcommand("enum", "Scaffold a typed enum: struct make enum NAME --values=A,B,C", makeEnum),
		makeSubcommand("policy", "Scaffold an authz policy + its unit test, deny-by-default", makePolicy),
		makeSubcommand("event", "Scaffold a versioned domain event + a consumer stub", makeEvent),
		makeSubcommand("job", "Scaffold a background worker under internal/support/queue", makeJob),
	)
	root.AddCommand(newMakeLocaleCmd())
	root.AddCommand(newMakeRPCCmd())
	return root
}

type makeFunc func(modulePath string, args []string) error

func makeSubcommand(use, short string, fn makeFunc) *Command {
	return &Command{
		Use:   use,
		Short: short,
		Run: func(args []string) error {
			modulePath, err := codegen.ModulePath()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return fmt.Errorf("cli: struct make %s requires a NAME argument", use)
			}
			return fn(modulePath, args)
		},
	}
}

func makeModel(modulePath string, args []string) error {
	path, source := codegen.Model(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeDTO(modulePath string, args []string) error {
	path, source := codegen.DTO(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeEnum(modulePath string, args []string) error {
	fs := FlagSet("make enum")
	values := fs.String("values", "", "comma-separated enum values, e.g. --values=pending,active,closed")
	name, rest := args[0], args[1:]
	if err := fs.Parse(rest); err != nil {
		return err
	}
	if *values == "" {
		return fmt.Errorf("cli: struct make enum %s requires --values=A,B,C", name)
	}
	vals := splitAndTrim(*values)
	if len(vals) == 0 {
		return fmt.Errorf("cli: --values must list at least one value")
	}
	path, source := codegen.Enum(modulePath, name, vals)
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeService(modulePath string, args []string) error {
	path, source := codegen.Service(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeController(modulePath string, args []string) error {
	path, source := codegen.Controller(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makePolicy(modulePath string, args []string) error {
	implPath, implSource, testPath, testSource := codegen.Policy(modulePath, args[0])
	if err := codegen.WriteGoFile(implPath, implSource); err != nil {
		return err
	}
	if err := codegen.WriteGoFile(testPath, testSource); err != nil {
		return err
	}
	fmt.Println("created", implPath)
	fmt.Println("created", testPath)
	return nil
}

func makeEvent(modulePath string, args []string) error {
	path, source := codegen.Event(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeJob(modulePath string, args []string) error {
	path, source := codegen.Job(modulePath, args[0])
	if err := codegen.WriteGoFile(path, source); err != nil {
		return err
	}
	fmt.Println("created", path)
	return nil
}

func makeRepository(modulePath string, args []string) error {
	pgPath, pgSource := codegen.RepositoryPostgres(modulePath, args[0])
	if err := codegen.WriteGoFile(pgPath, pgSource); err != nil {
		return err
	}
	myPath, mySource := codegen.RepositoryMySQL(modulePath, args[0])
	if err := codegen.WriteGoFile(myPath, mySource); err != nil {
		return err
	}
	fmt.Println("created", pgPath)
	fmt.Println("created", myPath)
	return nil
}

func splitAndTrim(csv string) []string {
	parts := strings.Split(csv, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func makeResource(modulePath string, args []string) error {
	name := args[0]
	if err := makeModel(modulePath, []string{name}); err != nil {
		return err
	}
	if err := makeDTO(modulePath, []string{name}); err != nil {
		return err
	}
	if err := makeService(modulePath, []string{name}); err != nil {
		return err
	}
	if err := makeRepository(modulePath, []string{name}); err != nil {
		return err
	}
	if err := makeController(modulePath, []string{name}); err != nil {
		return err
	}
	return nil
}
