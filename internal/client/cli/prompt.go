package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/magicelemental11/gophkeeper/internal/client/config"
)

// ErrNoTerminal is returned when input is needed but stdin is not a terminal.
var ErrNoTerminal = errors.New("stdin is not a terminal: set " + config.EnvPassword + " or pass the values with flags")

// Prompter asks the user for input.
type Prompter interface {
	Password(prompt string) (string, error)
	Line(prompt string) (string, error)
}

// TerminalPrompter reads from a terminal; passwords are not echoed.
type TerminalPrompter struct {
	in     *os.File
	out    io.Writer
	reader *bufio.Reader
}

// NewTerminalPrompter returns a prompter reading from in and writing prompts to out.
func NewTerminalPrompter(in *os.File, out io.Writer) *TerminalPrompter {
	return &TerminalPrompter{in: in, out: out, reader: bufio.NewReader(in)}
}

// Password reads a line without echo.
func (p *TerminalPrompter) Password(prompt string) (string, error) {
	fd := int(p.in.Fd())
	if !term.IsTerminal(fd) {
		return "", ErrNoTerminal
	}
	fmt.Fprint(p.out, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(p.out)
	return string(b), err
}

// Line reads a visible line.
func (p *TerminalPrompter) Line(prompt string) (string, error) {
	if !term.IsTerminal(int(p.in.Fd())) {
		return "", ErrNoTerminal
	}
	fmt.Fprint(p.out, prompt)
	line, err := p.reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
