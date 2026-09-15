package cli

func NewRootCommand() *Command {
	root := &Command{
		Use:   "struct",
		Short: "Struct — a typed-first Go microservice framework",
	}

	root.AddCommand(
		newNewCmd(),
		newServeCmd(),
		newRoutesCmd(),
		newHealthCmd(),
		newVersionCmd(),
		newAboutCmd(),
		newDoctorCmd(),
		newMakeCmd(),
		newMigrateCmd(),
		newLintCmd(),
		newCompletionCmd(),
		newRelayCmd(),
		newReportCmd(),
	)
	return root
}
