// Help routing: cobra's own help output, with a fallback to the root's help.

package cli

import "github.com/spf13/cobra"

func helpCommand(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "help [command]",
		Short: "Show the usage of any command",
		RunE: func(cmd *cobra.Command, args []string) error {
			target, _, err := root.Find(args)
			if err != nil {
				return usagef(cmd, "%s", err)
			}
			return target.Help()
		},
	}
}
