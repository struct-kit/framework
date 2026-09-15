package cli

import (
	"fmt"

	"struct-framework/internal/app/codegen"
)

func newMakeRPCCmd() *Command {
	return &Command{
		Use:   "rpc",
		Short: "Scaffold an internal RPC contract + client + server handler stub",
		Run: func(args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("cli: struct make rpc requires a NAME argument")
			}
			modulePath, err := codegen.ModulePath()
			if err != nil {
				return err
			}
			return makeRPCFiles(modulePath, args[0])
		},
	}
}

func makeRPCFiles(modulePath, name string) error {
	contractPath, contractSource, clientPath, clientSource, serverPath, serverSource := codegen.RPC(modulePath, name)

	if err := codegen.WriteGoFile(contractPath, contractSource); err != nil {
		return err
	}
	if err := codegen.WriteGoFile(clientPath, clientSource); err != nil {
		return err
	}
	if err := codegen.WriteGoFile(serverPath, serverSource); err != nil {
		return err
	}

	fmt.Println("created", contractPath)
	fmt.Println("created", clientPath)
	fmt.Println("created", serverPath)
	return nil
}
