package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/magicelemental11/gophkeeper/internal/vault"
)

const (
	metaWidth  = 30
	timeLayout = "2006-01-02 15:04"
	mask       = "********"
)

func (r *runner) listCmd() *cobra.Command {
	var kind string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List records without secrets",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var k vault.Kind
			if kind != "" {
				var err error
				if k, err = vault.ParseKind(kind); err != nil {
					return err
				}
			}
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			records, err := a.List(k)
			if err != nil {
				return err
			}
			if len(records) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No records.")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "ID\tKIND\tNAME\tMETA\tUPDATED")
			for _, rec := range records {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", shortID(rec), rec.Kind(), rec.Name,
					truncate(firstLine(rec.Meta), metaWidth), rec.UpdatedAt.Local().Format(timeLayout))
			}
			if pending := a.Pending(); pending > 0 {
				fmt.Fprintf(w, "\n%d local changes not sent yet, run sync.\n", pending)
			}
			return w.Flush()
		},
	}
	cmd.Flags().StringVarP(&kind, "kind", "k", "", "only records of this kind: credentials, text, binary, card, otp")
	return cmd
}

func (r *runner) showCmd() *cobra.Command {
	var reveal bool
	cmd := &cobra.Command{
		Use:   "show <id|name>",
		Short: "Show a record; secrets are hidden unless --reveal is given",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rec, err := a.Find(args[0])
			if err != nil {
				return err
			}
			printRecord(cmd.OutOrStdout(), rec, reveal, r.deps.Now())
			return nil
		},
	}
	cmd.Flags().BoolVarP(&reveal, "reveal", "r", false, "show passwords, CVV, card numbers and OTP secrets")
	return cmd
}

func (r *runner) deleteCmd() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:   "delete <id|name>",
		Short: "Delete a record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rec, err := a.Find(args[0])
			if err != nil {
				return err
			}
			if !yes {
				answer, err := r.deps.Prompter.Line(fmt.Sprintf("Delete %s %q? [y/N]: ", rec.Kind(), rec.Name))
				if err != nil {
					return err
				}
				if a := strings.ToLower(strings.TrimSpace(answer)); a != "y" && a != "yes" {
					fmt.Fprintln(cmd.OutOrStdout(), "Cancelled.")
					return nil
				}
			}
			rep, err := a.Delete(cmd.Context(), rec.ID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %q.\n", rec.Name)
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "do not ask for confirmation")
	return cmd
}

func (r *runner) getFileCmd() *cobra.Command {
	var out string
	var force bool
	cmd := &cobra.Command{
		Use:   "get-file <id|name>",
		Short: "Save the data of a binary record to a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rec, err := a.Find(args[0])
			if err != nil {
				return err
			}
			bin, ok := rec.Data.(vault.Binary)
			if !ok {
				return fmt.Errorf("%q is a %s record, not binary", rec.Name, rec.Kind())
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if force {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			f, err := os.OpenFile(out, flags, 0o600)
			if errors.Is(err, os.ErrExist) {
				return fmt.Errorf("%s exists, use --force to overwrite", out)
			}
			if err != nil {
				return err
			}
			if err := f.Chmod(0o600); err != nil {
				f.Close()
				return err
			}
			if _, err := f.Write(bin.Content); err != nil {
				f.Close()
				return err
			}
			if err := f.Close(); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Saved %d bytes to %s.\n", len(bin.Content), out)
			return nil
		},
	}
	cmd.Flags().StringVarP(&out, "output", "o", "", "output file")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite an existing file")
	cmd.MarkFlagRequired("output")
	return cmd
}

func (r *runner) otpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "otp <id|name>",
		Short: "Print the current one-time code of an OTP record",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rec, err := a.Find(args[0])
			if err != nil {
				return err
			}
			o, ok := rec.Data.(vault.OTP)
			if !ok {
				return fmt.Errorf("%q is a %s record, not otp", rec.Name, rec.Kind())
			}
			code, left, err := o.Code(r.deps.Now())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (valid for %d s)\n", code, int(left.Seconds()))
			return nil
		},
	}
}

func printRecord(w io.Writer, rec vault.Record, reveal bool, now time.Time) {
	hide := func(s string) string {
		if reveal || s == "" {
			return s
		}
		return mask
	}
	tw := tabwriter.NewWriter(w, 0, 0, 1, ' ', 0)
	fmt.Fprintf(tw, "ID:\t%s\n", rec.ID)
	fmt.Fprintf(tw, "Name:\t%s\n", rec.Name)
	fmt.Fprintf(tw, "Kind:\t%s\n", rec.Kind())
	fmt.Fprintf(tw, "Updated:\t%s\n", rec.UpdatedAt.Local().Format(timeLayout))
	switch d := rec.Data.(type) {
	case vault.Credentials:
		fmt.Fprintf(tw, "Login:\t%s\n", d.Login)
		fmt.Fprintf(tw, "Password:\t%s\n", hide(d.Password))
	case vault.Text:
		fmt.Fprintf(tw, "Text:\t\n")
	case vault.Binary:
		fmt.Fprintf(tw, "File:\t%s\n", d.FileName)
		fmt.Fprintf(tw, "Size:\t%d bytes\n", len(d.Content))
	case vault.Card:
		number := d.Number
		if !reveal && len(number) > 4 {
			number = "****" + number[len(number)-4:]
		}
		expiry := d.Expiry
		if d.Expired(now) {
			expiry += " (expired)"
		}
		fmt.Fprintf(tw, "Number:\t%s\n", number)
		fmt.Fprintf(tw, "Holder:\t%s\n", d.Holder)
		fmt.Fprintf(tw, "Expiry:\t%s\n", expiry)
		fmt.Fprintf(tw, "CVV:\t%s\n", hide(d.CVV))
	case vault.OTP:
		fmt.Fprintf(tw, "Issuer:\t%s\n", d.Issuer)
		fmt.Fprintf(tw, "Account:\t%s\n", d.Account)
		fmt.Fprintf(tw, "Secret:\t%s\n", hide(d.Secret))
		fmt.Fprintf(tw, "Params:\t%d digits, %d s, %s\n", d.Digits, d.Period, d.Algorithm)
	}
	tw.Flush()
	if t, ok := rec.Data.(vault.Text); ok {
		fmt.Fprintln(w, t.Content)
	}
	if rec.Meta != "" {
		fmt.Fprintf(w, "Meta:\n%s\n", rec.Meta)
	}
}

func shortID(rec vault.Record) string {
	return rec.ID.String()[:8]
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
