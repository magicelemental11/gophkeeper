// Package cli implements the gophkeeper command line client on top of the app package.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/magicelemental11/gophkeeper/internal/buildinfo"
	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/client/config"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
)

// Deps are the outside dependencies of the commands, replaced in tests.
type Deps struct {
	Dial     func(server, caPath string, insecure bool) (app.Remote, error)
	Derive   func(login, password string) (crypto.Keys, error)
	Prompter Prompter
	Now      func() time.Time
}

// DefaultDeps connects with api.Dial, derives keys with crypto.Derive and prompts on the terminal.
func DefaultDeps() Deps {
	return Deps{
		Dial: func(server, caPath string, insecure bool) (app.Remote, error) {
			return api.Dial(server, caPath, insecure)
		},
		Derive:   crypto.Derive,
		Prompter: NewTerminalPrompter(os.Stdin, os.Stderr),
		Now:      time.Now,
	}
}

type runner struct {
	deps  Deps
	flags config.Config
}

// NewRoot returns the root command with all subcommands.
func NewRoot(deps Deps) *cobra.Command {
	r := &runner{deps: deps}
	root := &cobra.Command{
		Use:           "gophkeeper",
		Short:         "GophKeeper password manager client",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	pf := root.PersistentFlags()
	pf.StringVarP(&r.flags.Server, "server", "s", "", "server address (env "+config.EnvServer+", default "+config.DefaultServer+")")
	pf.StringVar(&r.flags.CA, "ca", "", "CA certificate to verify the server (env "+config.EnvCA+")")
	pf.StringVar(&r.flags.DataDir, "data-dir", "", "local data directory (env "+config.EnvDataDir+")")
	pf.BoolVar(&r.flags.Insecure, "insecure", false, "connect without TLS (local tests only)")

	root.AddCommand(
		versionCmd(),
		r.registerCmd(), r.loginCmd(), r.logoutCmd(), r.syncCmd(),
		r.listCmd(), r.showCmd(), r.addCmd(), r.editCmd(), r.deleteCmd(), r.getFileCmd(), r.otpCmd(), r.tuiCmd(),
	)
	return root
}

// Execute runs the root command with args and prints an error to stderr. It returns the exit code.
func Execute(ctx context.Context, root *cobra.Command, args []string) int {
	root.SetArgs(args)
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintln(root.ErrOrStderr(), "error:", err)
		return 1
	}
	return 0
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version and build date",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			buildinfo.Fprint(cmd.OutOrStdout(), "gophkeeper")
		},
	}
}

func (r *runner) config() config.Config {
	return config.Resolve(r.flags)
}

func (r *runner) open() (*app.App, error) {
	cfg := r.config()
	return app.New(app.Config{
		DataDir: cfg.DataDir,
		Dial: func(server string) (app.Remote, error) {
			return r.deps.Dial(server, cfg.CA, cfg.Insecure)
		},
		Derive: r.deps.Derive,
		Now:    r.deps.Now,
	})
}

func (r *runner) masterPassword(prompt string) (string, error) {
	if p := os.Getenv(config.EnvPassword); p != "" {
		return p, nil
	}
	return r.deps.Prompter.Password(prompt)
}

func (r *runner) openUnlocked() (*app.App, error) {
	a, err := r.open()
	if err != nil {
		return nil, err
	}
	if _, ok := a.Session(); !ok {
		return nil, app.ErrNotLoggedIn
	}
	password, err := r.masterPassword("Master password: ")
	if err != nil {
		return nil, err
	}
	if err := a.Unlock(password); err != nil {
		return nil, err
	}
	return a, nil
}

func printReport(w io.Writer, rep app.Report) {
	if rep.Offline {
		fmt.Fprintln(w, "Saved locally: the server is unavailable, run sync later.")
		return
	}
	fmt.Fprintf(w, "Synced: sent %d, received %d, conflicts %d.\n", rep.Pushed, rep.Pulled, rep.Conflicts)
	if rep.Conflicts > 0 {
		fmt.Fprintln(w, "Conflicting local versions were kept as records named \"<name> (conflict <time>)\".")
	}
}
