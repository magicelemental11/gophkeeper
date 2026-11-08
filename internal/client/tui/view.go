package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/magicelemental11/gophkeeper/internal/vault"
)

var (
	titleStyle    = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	selectedStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))
	dimStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("8"))
	errorStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
)

const hidden = "********"

// View renders the current screen.
func (m Model) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("GophKeeper") + "\n\n")
	switch m.screen {
	case screenLogin:
		m.viewForm(&b, "Log in", "enter: log in  ctrl+r: register  tab: next field  esc: quit")
	case screenList:
		m.viewList(&b)
	case screenDetail:
		m.viewDetail(&b)
	case screenPickKind:
		b.WriteString("New record kind:\n\n")
		for i, k := range vault.Kinds {
			fmt.Fprintf(&b, "  %d  %s\n", i+1, k)
		}
		b.WriteString(dimStyle.Render("\n1-5: choose  esc: back") + "\n")
	case screenForm:
		title := "New " + string(m.formKind)
		if m.editing {
			title = "Edit " + m.current.Name
		}
		m.viewForm(&b, title, "tab: next field  enter/ctrl+s: save  esc: cancel")
	case screenConfirm:
		fmt.Fprintf(&b, "Delete %s %q? (y/n)\n", m.current.Kind(), m.current.Name)
	}
	b.WriteString("\n")
	if m.busy {
		b.WriteString(dimStyle.Render("working...") + "\n")
	}
	if m.status != "" {
		b.WriteString(dimStyle.Render("status: "+m.status) + "\n")
	}
	if m.errText != "" {
		b.WriteString(errorStyle.Render("error: "+m.errText) + "\n")
	}
	return b.String()
}

func (m Model) viewForm(b *strings.Builder, title, help string) {
	b.WriteString(title + "\n\n")
	for i, in := range m.inputs {
		marker := "  "
		if i == m.focus {
			marker = "> "
		}
		fmt.Fprintf(b, "%s%s: %s\n", marker, m.labels[i], in.View())
	}
	b.WriteString(dimStyle.Render("\n"+help) + "\n")
}

func (m Model) viewList(b *strings.Builder) {
	filter := "all"
	if m.kindFilter > 0 {
		filter = string(vault.Kinds[m.kindFilter-1])
	}
	fmt.Fprintf(b, "Records (%s)", filter)
	if m.searching || m.search.Value() != "" {
		b.WriteString("  " + m.search.View())
	}
	b.WriteString("\n\n")
	visible := m.visible()
	if len(visible) == 0 {
		b.WriteString(dimStyle.Render("  no records") + "\n")
	}
	for i, r := range visible {
		line := fmt.Sprintf("%-12s %s", r.Kind(), r.Name)
		if meta, _, _ := strings.Cut(r.Meta, "\n"); meta != "" {
			line += dimStyle.Render("  " + meta)
		}
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("> "+line) + "\n")
		} else {
			b.WriteString("  " + line + "\n")
		}
	}
	b.WriteString(dimStyle.Render("\nenter: open  a: add  e: edit  d: delete  /: search  f: filter kind  s: sync  L: log in again  q: quit") + "\n")
}

func (m Model) viewDetail(b *strings.Builder) {
	r := m.current
	secret := func(s string) string {
		if m.reveal || s == "" {
			return s
		}
		return hidden
	}
	fmt.Fprintf(b, "%s  (%s)\n\n", r.Name, r.Kind())
	switch d := r.Data.(type) {
	case vault.Credentials:
		fmt.Fprintf(b, "Login:    %s\nPassword: %s\n", d.Login, secret(d.Password))
	case vault.Text:
		b.WriteString(d.Content + "\n")
	case vault.Binary:
		fmt.Fprintf(b, "File: %s\nSize: %d bytes\n", d.FileName, len(d.Content))
	case vault.Card:
		number := d.Number
		if !m.reveal && len(number) > 4 {
			number = "****" + number[len(number)-4:]
		}
		expiry := d.Expiry
		if d.Expired(m.now()) {
			expiry += " (expired)"
		}
		fmt.Fprintf(b, "Number: %s\nHolder: %s\nExpiry: %s\nCVV:    %s\n", number, d.Holder, expiry, secret(d.CVV))
	case vault.OTP:
		fmt.Fprintf(b, "Issuer:  %s\nAccount: %s\nSecret:  %s\n", d.Issuer, d.Account, secret(d.Secret))
		if code, left, err := d.Code(m.now()); err == nil {
			fmt.Fprintf(b, "\nCode: %s  (%d s left)\n", selectedStyle.Render(code), int(left.Seconds()))
		}
	}
	if r.Meta != "" {
		fmt.Fprintf(b, "\nMeta:\n%s\n", r.Meta)
	}
	fmt.Fprintf(b, "\n%s\n", dimStyle.Render("Updated "+r.UpdatedAt.Local().Format("2006-01-02 15:04")))
	b.WriteString(dimStyle.Render("\nr: reveal secrets  e: edit  d: delete  esc: back") + "\n")
}
