package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/magicelemental11/gophkeeper/internal/vault"
)

type recordFlags struct {
	name, meta, metaFile string

	login         string
	passwordStdin bool
	askPassword   bool

	content, file string

	number, holder, expiry string
	cvvStdin, askCVV       bool

	uri, secret, issuer, account, algorithm string
	digits, period                          int
}

var addShort = map[vault.Kind]string{
	vault.KindCredentials: "Add a login and password",
	vault.KindText:        "Add a text from a flag, a file or stdin",
	vault.KindBinary:      "Add binary data from a file",
	vault.KindCard:        "Add a bank card",
	vault.KindOTP:         "Add a TOTP generator",
}

var kindFlags = map[vault.Kind][]string{
	vault.KindCredentials: {"login", "password-stdin", "password"},
	vault.KindText:        {"content", "file"},
	vault.KindBinary:      {"file"},
	vault.KindCard:        {"number", "holder", "expiry", "cvv-stdin", "cvv"},
	vault.KindOTP:         {"uri", "secret", "issuer", "account", "digits", "period", "algorithm"},
}

func (f *recordFlags) common(fs *pflag.FlagSet) {
	fs.StringVar(&f.name, "name", "", "record name")
	fs.StringVar(&f.meta, "meta", "", "free text metadata: site, bank, notes")
	fs.StringVar(&f.metaFile, "meta-file", "", "read metadata from a file")
}

func (f *recordFlags) register(fs *pflag.FlagSet, kind vault.Kind, edit bool) {
	switch kind {
	case vault.KindCredentials:
		fs.StringVar(&f.login, "login", "", "login")
		fs.BoolVar(&f.passwordStdin, "password-stdin", false, "read the password from the first line of stdin")
		if edit {
			fs.BoolVar(&f.askPassword, "password", false, "ask for a new password")
		}
	case vault.KindText:
		fs.StringVar(&f.content, "content", "", "text content")
		fs.StringVar(&f.file, "file", "", "read the text from a file")
	case vault.KindBinary:
		fs.StringVar(&f.file, "file", "", "file with the binary data")
	case vault.KindCard:
		fs.StringVar(&f.number, "number", "", "card number, spaces allowed")
		fs.StringVar(&f.holder, "holder", "", "card holder")
		fs.StringVar(&f.expiry, "expiry", "", "expiry date MM/YY")
		fs.BoolVar(&f.cvvStdin, "cvv-stdin", false, "read the CVV from the first line of stdin")
		if edit {
			fs.BoolVar(&f.askCVV, "cvv", false, "ask for a new CVV")
		}
	case vault.KindOTP:
		fs.StringVar(&f.uri, "uri", "", "otpauth://totp/ URI from the QR code")
		fs.StringVar(&f.secret, "secret", "", "base32 secret")
		fs.StringVar(&f.issuer, "issuer", "", "issuer")
		fs.StringVar(&f.account, "account", "", "account")
		fs.IntVar(&f.digits, "digits", 0, "code length (default 6)")
		fs.IntVar(&f.period, "period", 0, "code period in seconds (default 30)")
		fs.StringVar(&f.algorithm, "algorithm", "", "SHA1, SHA256 or SHA512 (default SHA1)")
	}
}

func (r *runner) addCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a record",
	}
	for _, kind := range vault.Kinds {
		cmd.AddCommand(r.addKindCmd(kind))
	}
	return cmd
}

func (r *runner) addKindCmd(kind vault.Kind) *cobra.Command {
	f := &recordFlags{}
	cmd := &cobra.Command{
		Use:   string(kind),
		Short: addShort[kind],
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			meta, err := f.metaValue(cmd, "")
			if err != nil {
				return err
			}
			data, err := r.buildData(cmd, f, emptyData(kind), false)
			if err != nil {
				return err
			}
			rec := vault.New(f.name, meta, data)
			if err := rec.Validate(); err != nil {
				return err
			}
			a, err := r.openUnlocked()
			if err != nil {
				return err
			}
			defer a.Close()
			rep, err := a.Add(cmd.Context(), rec)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Added %s %q (%s).\n", kind, rec.Name, shortID(rec))
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	f.common(cmd.Flags())
	f.register(cmd.Flags(), kind, false)
	cmd.MarkFlagRequired("name")
	switch kind {
	case vault.KindBinary:
		cmd.MarkFlagRequired("file")
	case vault.KindCard:
		cmd.MarkFlagRequired("number")
		cmd.MarkFlagRequired("expiry")
	case vault.KindOTP:
		cmd.MarkFlagsOneRequired("uri", "secret")
		cmd.MarkFlagsMutuallyExclusive("uri", "secret")
	case vault.KindText:
		cmd.MarkFlagsMutuallyExclusive("content", "file")
	}
	return cmd
}

func (r *runner) editCmd() *cobra.Command {
	f := &recordFlags{}
	cmd := &cobra.Command{
		Use:   "edit <id|name>",
		Short: "Change the given fields of a record",
		Long:  "Change the given fields of a record. Flags of the record kind are the same as for add.",
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
			if err := checkEditFlags(cmd, rec.Kind()); err != nil {
				return err
			}
			if rec.Meta, err = f.metaValue(cmd, rec.Meta); err != nil {
				return err
			}
			if cmd.Flags().Changed("name") {
				rec.Name = f.name
			}
			data, err := r.buildData(cmd, f, rec.Data, true)
			if err != nil {
				return err
			}
			rec.SetData(data)
			rep, err := a.Update(cmd.Context(), rec)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Updated %q (%s).\n", rec.Name, shortID(rec))
			printReport(cmd.OutOrStdout(), rep)
			return nil
		},
	}
	f.common(cmd.Flags())
	for _, kind := range vault.Kinds {
		if kind != vault.KindBinary {
			f.register(cmd.Flags(), kind, true)
		}
	}
	return cmd
}

func checkEditFlags(cmd *cobra.Command, kind vault.Kind) error {
	var wrong []string
	cmd.Flags().Visit(func(fl *pflag.Flag) {
		if slices.Contains([]string{"name", "meta", "meta-file"}, fl.Name) || slices.Contains(kindFlags[kind], fl.Name) {
			return
		}
		if cmd.InheritedFlags().Lookup(fl.Name) == nil {
			wrong = append(wrong, "--"+fl.Name)
		}
	})
	if len(wrong) > 0 {
		return fmt.Errorf("%s not applicable to a %s record", strings.Join(wrong, ", "), kind)
	}
	return nil
}

func emptyData(kind vault.Kind) vault.Data {
	switch kind {
	case vault.KindCredentials:
		return vault.Credentials{}
	case vault.KindText:
		return vault.Text{}
	case vault.KindBinary:
		return vault.Binary{}
	case vault.KindCard:
		return vault.Card{}
	}
	return vault.OTP{}
}

func (f *recordFlags) metaValue(cmd *cobra.Command, current string) (string, error) {
	switch {
	case cmd.Flags().Changed("meta-file"):
		b, err := os.ReadFile(f.metaFile)
		return string(b), err
	case cmd.Flags().Changed("meta"):
		return f.meta, nil
	}
	return current, nil
}

func (r *runner) buildData(cmd *cobra.Command, f *recordFlags, prev vault.Data, edit bool) (vault.Data, error) {
	changed := cmd.Flags().Changed
	switch d := prev.(type) {
	case vault.Credentials:
		if changed("login") {
			d.Login = f.login
		}
		if f.passwordStdin || !edit || f.askPassword {
			p, err := r.secret(cmd, f.passwordStdin, "Record password: ")
			if err != nil {
				return nil, err
			}
			d.Password = p
		}
		return d, nil
	case vault.Text:
		switch {
		case changed("content"):
			d.Content = f.content
		case changed("file"):
			b, err := os.ReadFile(f.file)
			if err != nil {
				return nil, err
			}
			d.Content = string(b)
		case !edit:
			b, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return nil, err
			}
			d.Content = string(b)
		}
		return d, nil
	case vault.Binary:
		if changed("file") {
			return vault.ReadBinaryFile(f.file)
		}
		return d, nil
	case vault.Card:
		if changed("number") {
			d.Number = f.number
		}
		if changed("holder") {
			d.Holder = f.holder
		}
		if changed("expiry") {
			d.Expiry = f.expiry
		}
		if f.cvvStdin || !edit || f.askCVV {
			cvv, err := r.secret(cmd, f.cvvStdin, "CVV: ")
			if err != nil {
				return nil, err
			}
			d.CVV = cvv
		}
		return d, nil
	case vault.OTP:
		return otpData(cmd, f, d)
	}
	return nil, errors.New("unsupported record kind")
}

func otpData(cmd *cobra.Command, f *recordFlags, d vault.OTP) (vault.Data, error) {
	changed := cmd.Flags().Changed
	if changed("uri") {
		parsed, err := vault.ParseOTPURI(f.uri)
		if err != nil {
			return nil, err
		}
		d = parsed
	}
	if changed("secret") {
		d.Secret = f.secret
	}
	if changed("issuer") {
		d.Issuer = f.issuer
	}
	if changed("account") {
		d.Account = f.account
	}
	if changed("digits") {
		d.Digits = f.digits
	}
	if changed("period") {
		d.Period = f.period
	}
	if changed("algorithm") {
		d.Algorithm = f.algorithm
	}
	return d.WithDefaults(), nil
}

func (r *runner) secret(cmd *cobra.Command, fromStdin bool, prompt string) (string, error) {
	if !fromStdin {
		return r.deps.Prompter.Password(prompt)
	}
	line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}
