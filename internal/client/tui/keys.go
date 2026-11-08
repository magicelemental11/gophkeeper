package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

func (m Model) onKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch m.screen {
	case screenLogin:
		return m.loginKey(msg)
	case screenList:
		return m.listKey(msg)
	case screenDetail:
		return m.detailKey(msg)
	case screenPickKind:
		return m.pickKindKey(msg)
	case screenForm:
		return m.formKey(msg)
	case screenConfirm:
		return m.confirmKey(msg)
	}
	return m, nil
}

func newInput(label, value string, secret bool) textinput.Model {
	in := textinput.New()
	in.Prompt = ""
	in.CharLimit = 4096
	in.SetValue(value)
	if secret {
		in.EchoMode = textinput.EchoPassword
	}
	return in
}

func (m *Model) setInputs(labels, values []string, secret []bool) {
	m.labels = labels
	m.inputs = make([]textinput.Model, len(labels))
	for i := range labels {
		m.inputs[i] = newInput(labels[i], values[i], secret[i])
	}
	m.focus = 0
	m.inputs[0].Focus()
}

func (m *Model) openLogin(full bool) {
	m.screen = screenLogin
	if s, ok := m.backend.Session(); ok && !full {
		m.setInputs([]string{"Master password for " + s.Login}, []string{""}, []bool{true})
		return
	}
	m.setInputs([]string{"Server", "Login", "Master password"}, []string{m.server, "", ""}, []bool{false, false, true})
	m.focus = 1
	m.inputs[0].Blur()
	m.inputs[1].Focus()
}

func (m *Model) moveFocus(delta int) {
	m.inputs[m.focus].Blur()
	m.focus = (m.focus + delta + len(m.inputs)) % len(m.inputs)
	m.inputs[m.focus].Focus()
}

func (m Model) editInputs(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	m.inputs[m.focus], cmd = m.inputs[m.focus].Update(msg)
	return m, cmd
}

func (m Model) loginKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		return m, tea.Quit
	case "tab", "down":
		m.moveFocus(1)
		return m, nil
	case "shift+tab", "up":
		m.moveFocus(-1)
		return m, nil
	case "enter", "ctrl+r":
		m.busy = true
		register := msg.String() == "ctrl+r"
		if len(m.inputs) == 1 {
			password := m.inputs[0].Value()
			return m, m.run("login", screenList, func() (app.Report, error) {
				return app.Report{}, m.backend.Unlock(password)
			})
		}
		server, login, password := m.inputs[0].Value(), m.inputs[1].Value(), m.inputs[2].Value()
		return m, m.run("login", screenList, func() (app.Report, error) {
			if register {
				return m.backend.Register(m.ctx, server, login, password)
			}
			return m.backend.Login(m.ctx, server, login, password)
		})
	}
	return m.editInputs(msg)
}

func (m Model) listKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.searching {
		switch msg.String() {
		case "enter", "esc":
			m.searching = false
			m.search.Blur()
			if msg.String() == "esc" {
				m.search.SetValue("")
			}
			m.cursor = 0
			return m, nil
		}
		var cmd tea.Cmd
		m.search, cmd = m.search.Update(msg)
		m.cursor = 0
		return m, cmd
	}
	visible := m.visible()
	switch msg.String() {
	case "q", "esc":
		return m, tea.Quit
	case "up", "k":
		m.cursor = max(0, m.cursor-1)
	case "down", "j":
		m.cursor = min(max(0, len(visible)-1), m.cursor+1)
	case "/":
		m.searching = true
		return m, m.search.Focus()
	case "f":
		m.kindFilter = (m.kindFilter + 1) % (len(vault.Kinds) + 1)
		m.cursor = 0
	case "a":
		m.screen = screenPickKind
	case "L":
		m.openLogin(true)
	case "s":
		m.busy = true
		return m, m.run("sync", screenList, func() (app.Report, error) { return m.backend.Sync(m.ctx) })
	case "enter", "e", "d":
		if len(visible) == 0 {
			return m, nil
		}
		m.current, m.reveal = visible[m.cursor], false
		return m.recordAction(msg.String())
	}
	return m, nil
}

func (m Model) recordAction(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		m.screen = screenDetail
	case "e":
		m.openForm(m.current.Kind(), &m.current)
	case "d":
		m.screen = screenConfirm
	}
	return m, nil
}

func (m Model) detailKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "q":
		m.screen = screenList
	case "r":
		m.reveal = !m.reveal
	case "e", "d":
		return m.recordAction(msg.String())
	}
	return m, nil
}

func (m Model) pickKindKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.screen = screenList
		return m, nil
	}
	n, err := strconv.Atoi(msg.String())
	if err != nil || n < 1 || n > len(vault.Kinds) {
		return m, nil
	}
	m.openForm(vault.Kinds[n-1], nil)
	return m, nil
}

func (m Model) confirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "y":
		m.busy = true
		id := m.current.ID
		return m, m.run("delete", screenList, func() (app.Report, error) { return m.backend.Delete(m.ctx, id) })
	case "n", "esc":
		m.screen = screenList
	}
	return m, nil
}

func (m *Model) openForm(kind vault.Kind, rec *vault.Record) {
	m.screen, m.formKind, m.editing = screenForm, kind, rec != nil
	labels := []string{"Name", "Meta"}
	values := []string{"", ""}
	secret := []bool{false, false}
	add := func(label, value string, hidden bool) {
		labels, values, secret = append(labels, label), append(values, value), append(secret, hidden)
	}
	if rec != nil {
		values[0], values[1] = rec.Name, rec.Meta
	}
	switch kind {
	case vault.KindCredentials:
		c, _ := dataOf[vault.Credentials](rec)
		add("Login", c.Login, false)
		add("Password", c.Password, true)
	case vault.KindText:
		t, _ := dataOf[vault.Text](rec)
		add("Text", t.Content, false)
	case vault.KindBinary:
		add("File path (empty keeps the data)", "", false)
	case vault.KindCard:
		c, _ := dataOf[vault.Card](rec)
		add("Number", c.Number, false)
		add("Holder", c.Holder, false)
		add("Expiry MM/YY", c.Expiry, false)
		add("CVV", c.CVV, true)
	case vault.KindOTP:
		o, _ := dataOf[vault.OTP](rec)
		add("Secret or otpauth:// URI", o.Secret, true)
		add("Issuer", o.Issuer, false)
		add("Account", o.Account, false)
	}
	m.setInputs(labels, values, secret)
}

func dataOf[T vault.Data](rec *vault.Record) (T, bool) {
	var zero T
	if rec == nil {
		return zero, false
	}
	d, ok := rec.Data.(T)
	return d, ok
}

func (m Model) formKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = screenList
		return m, nil
	case "tab", "down":
		m.moveFocus(1)
		return m, nil
	case "shift+tab", "up":
		m.moveFocus(-1)
		return m, nil
	case "enter":
		if m.focus < len(m.inputs)-1 {
			m.moveFocus(1)
			return m, nil
		}
		fallthrough
	case "ctrl+s":
		return m.submitForm()
	}
	return m.editInputs(msg)
}

func (m Model) submitForm() (tea.Model, tea.Cmd) {
	v := make([]string, len(m.inputs))
	for i, in := range m.inputs {
		v[i] = in.Value()
	}
	var prev *vault.Record
	if m.editing {
		prev = &m.current
	}
	data, err := formData(m.formKind, v[2:], prev)
	if err != nil {
		m.errText = err.Error()
		return m, nil
	}
	rec := vault.New(v[0], v[1], data)
	next := screenList
	if m.editing {
		rec = m.current
		rec.Name, rec.Meta = v[0], v[1]
		rec.SetData(data)
		next = screenDetail
	}
	if err := rec.Validate(); err != nil {
		m.errText = err.Error()
		return m, nil
	}
	m.busy = true
	m.current = rec
	if m.editing {
		return m, m.run("update", next, func() (app.Report, error) { return m.backend.Update(m.ctx, rec) })
	}
	return m, m.run("add", next, func() (app.Report, error) { return m.backend.Add(m.ctx, rec) })
}

func formData(kind vault.Kind, v []string, prev *vault.Record) (vault.Data, error) {
	switch kind {
	case vault.KindCredentials:
		return vault.Credentials{Login: v[0], Password: v[1]}, nil
	case vault.KindText:
		return vault.Text{Content: v[0]}, nil
	case vault.KindBinary:
		if v[0] == "" {
			if b, ok := dataOf[vault.Binary](prev); ok {
				return b, nil
			}
			return nil, fmt.Errorf("file path is required")
		}
		return vault.ReadBinaryFile(v[0])
	case vault.KindCard:
		return vault.Card{Number: v[0], Holder: v[1], Expiry: v[2], CVV: v[3]}, nil
	}
	if strings.HasPrefix(v[0], "otpauth://") {
		return vault.ParseOTPURI(v[0])
	}
	return vault.OTP{Secret: v[0], Issuer: v[1], Account: v[2]}.WithDefaults(), nil
}
