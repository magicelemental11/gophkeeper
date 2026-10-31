// Package tui is an interactive terminal interface on top of the app package.
package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/app"
	"github.com/magicelemental11/gophkeeper/internal/client/store"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

// SyncEvery is how often the TUI synchronizes in the background.
const SyncEvery = 30 * time.Second

// Backend is the client core used by the TUI; *app.App implements it.
type Backend interface {
	Session() (store.Session, bool)
	Register(ctx context.Context, server, login, password string) (app.Report, error)
	Login(ctx context.Context, server, login, password string) (app.Report, error)
	Unlock(password string) error
	List(kind vault.Kind) ([]vault.Record, error)
	Add(ctx context.Context, r vault.Record) (app.Report, error)
	Update(ctx context.Context, r vault.Record) (app.Report, error)
	Delete(ctx context.Context, id uuid.UUID) (app.Report, error)
	Sync(ctx context.Context) (app.Report, error)
	Pending() int
}

type screen int

const (
	screenLogin screen = iota
	screenList
	screenDetail
	screenPickKind
	screenForm
	screenConfirm
)

type tickMsg time.Time

type doneMsg struct {
	op      string
	report  app.Report
	records []vault.Record
	pending int
	err     error
	next    screen
}

// Model is the bubbletea model of the whole interface.
type Model struct {
	backend Backend
	ctx     context.Context
	server  string
	now     func() time.Time

	screen   screen
	busy     bool
	status   string
	errText  string
	unlocked bool
	ticks    int

	inputs []textinput.Model
	labels []string
	focus  int

	records    []vault.Record
	cursor     int
	kindFilter int
	search     textinput.Model
	searching  bool

	current  vault.Record
	reveal   bool
	formKind vault.Kind
	editing  bool
}

// New returns the model; server is used for logging in when there is no session.
func New(ctx context.Context, backend Backend, server string, now func() time.Time) Model {
	m := Model{backend: backend, ctx: ctx, server: server, now: now}
	m.search = textinput.New()
	m.search.Prompt = "/"
	m.openLogin(false)
	return m
}

// Init starts the clock that drives background sync and OTP countdowns.
func (m Model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tick())
}

func tick() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update handles a message and returns the next model and command.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tickMsg:
		return m.onTick()
	case doneMsg:
		return m.onDone(msg), nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.busy {
			return m, nil
		}
		m.errText = ""
		return m.onKey(msg)
	}
	return m.updateInputs(msg)
}

func (m Model) onTick() (tea.Model, tea.Cmd) {
	m.ticks++
	if m.unlocked && !m.busy && m.ticks%int(SyncEvery/time.Second) == 0 {
		m.busy = true
		return m, tea.Batch(tick(), m.run("sync", m.screen, func() (app.Report, error) { return m.backend.Sync(m.ctx) }))
	}
	return m, tick()
}

func (m Model) onDone(msg doneMsg) Model {
	m.busy = false
	if msg.records != nil || msg.err == nil {
		m.records = msg.records
	}
	if m.cursor >= len(m.visible()) {
		m.cursor = max(0, len(m.visible())-1)
	}
	m.status = statusLine(msg.report, msg.pending)
	switch {
	case msg.op != "login" && errors.Is(msg.err, api.ErrUnavailable):
		m.status = fmt.Sprintf("offline, %d changes not sent", msg.pending)
	case msg.err != nil:
		m.errText = msg.err.Error()
		if m.screen == screenLogin {
			m.inputs[len(m.inputs)-1].SetValue("")
		}
		return m
	}
	if msg.op == "login" {
		m.unlocked = true
	}
	m.screen = msg.next
	if m.screen == screenDetail {
		for _, r := range m.records {
			if r.ID == m.current.ID {
				m.current = r
			}
		}
	}
	return m
}

func statusLine(rep app.Report, pending int) string {
	switch {
	case rep.Offline:
		return fmt.Sprintf("offline, %d changes not sent", pending)
	case pending > 0:
		return fmt.Sprintf("%d changes not sent", pending)
	case rep.Conflicts > 0:
		return fmt.Sprintf("synced, conflicts: %d", rep.Conflicts)
	}
	return "synced"
}

func (m Model) run(op string, next screen, call func() (app.Report, error)) tea.Cmd {
	backend := m.backend
	return func() tea.Msg {
		rep, err := call()
		msg := doneMsg{op: op, report: rep, err: err, next: next}
		if err == nil || (op != "login" && errors.Is(err, api.ErrUnavailable)) {
			msg.records, msg.err = backendList(backend, msg.err)
		}
		msg.pending = backend.Pending()
		return msg
	}
}

func backendList(b Backend, prev error) ([]vault.Record, error) {
	records, err := b.List("")
	if err != nil {
		return nil, err
	}
	return records, prev
}

func (m Model) visible() []vault.Record {
	query := strings.ToLower(m.search.Value())
	var out []vault.Record
	for _, r := range m.records {
		if m.kindFilter > 0 && r.Kind() != vault.Kinds[m.kindFilter-1] {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Meta), query) {
			continue
		}
		out = append(out, r)
	}
	return out
}

func (m Model) updateInputs(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	for i := range m.inputs {
		var cmd tea.Cmd
		m.inputs[i], cmd = m.inputs[i].Update(msg)
		cmds = append(cmds, cmd)
	}
	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	return m, tea.Batch(append(cmds, cmd)...)
}
