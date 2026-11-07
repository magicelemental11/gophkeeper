package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/magicelemental11/gophkeeper/internal/client/config"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
)

func (r *runner) registerCmd() *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Create an account on the server and log in",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			login, err := r.askLogin(login)
			if err != nil {
				return err
			}
			password, err := r.newPassword()
			if err != nil {
				return err
			}
			a, err := r.open()
			if err != nil {
				return err
			}
			defer a.Close()
			rep, err := a.Register(cmd.Context(), r.cfg.Server, login, password)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Registered and logged in as %s.\n", login)
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login (asked when empty)")
	return cmd
}

func (r *runner) loginCmd() *cobra.Command {
	var login string
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Log into an existing account and synchronize",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			login, err := r.askLogin(login)
			if err != nil {
				return err
			}
			password, err := r.masterPassword("Master password: ")
			if err != nil {
				return err
			}
			a, err := r.open()
			if err != nil {
				return err
			}
			defer a.Close()
			rep, err := a.Login(cmd.Context(), r.cfg.Server, login, password)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Logged in as %s.\n", login)
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().StringVarP(&login, "login", "l", "", "account login (asked when empty)")
	return cmd
}

func (r *runner) logoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Forget the session and remove the local cache",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := r.open()
			if err != nil {
				return err
			}
			if err := a.Logout(); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Logged out.")
			return nil
		},
	}
}

func (r *runner) syncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Send local changes and fetch changes from other devices",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rep, err := a.Sync(cmd.Context())
			if err != nil {
				return err
			}
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
}

func (r *runner) askLogin(login string) (string, error) {
	if login != "" {
		return login, nil
	}
	return r.deps.Prompter.Line("Login: ")
}

func (r *runner) newPassword() (string, error) {
	p, ok, err := config.Password()
	switch {
	case err != nil:
		return "", err
	case ok:
		return p, crypto.ValidatePassword(p)
	}
	password, err := r.deps.Prompter.Password("New master password: ")
	if err != nil {
		return "", err
	}
	if err := crypto.ValidatePassword(password); err != nil {
		return "", err
	}
	confirm, err := r.deps.Prompter.Password("Repeat master password: ")
	if err != nil {
		return "", err
	}
	if confirm != password {
		return "", errors.New("passwords do not match")
	}
	return password, nil
}
