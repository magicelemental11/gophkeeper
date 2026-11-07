package cli

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	"github.com/magicelemental11/gophkeeper/internal/client/tui"
)

func (r *runner) tuiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive terminal interface",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := r.open()
			if err != nil {
				return err
			}
			defer a.Close()
			model := tui.New(cmd.Context(), a, r.cfg.Server, r.deps.Now)
			_, err = tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(cmd.Context()),
				tea.WithInput(cmd.InOrStdin()), tea.WithOutput(cmd.OutOrStdout())).Run()
			return err
		},
	}
}
