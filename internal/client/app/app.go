// Package app is the client core shared by the CLI and the TUI: login, the local encrypted cache,
// record operations and synchronization with the server.
package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/store"
	"github.com/magicelemental11/gophkeeper/internal/crypto"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

// Errors returned by App.
var (
	ErrNotLoggedIn    = errors.New("not logged in: run register or login first")
	ErrSessionExpired = errors.New("session expired: run login again")
	ErrWrongPassword  = errors.New("wrong master password")
	ErrLocked         = errors.New("vault is locked: master password required")
	ErrNotFound       = errors.New("record not found")
	ErrUnsentChanges  = errors.New("another account has unsent changes")
)

var checkPlaintext = []byte("gophkeeper")

// AmbiguousError is returned by Find when several records match.
type AmbiguousError struct {
	Query   string
	Matches []vault.Record
}

// Error lists the matching records with their short IDs.
func (e *AmbiguousError) Error() string {
	lines := make([]string, len(e.Matches))
	for i, r := range e.Matches {
		lines[i] = fmt.Sprintf("  %s  %s  %s", r.ID.String()[:8], r.Kind(), r.Name)
	}
	return fmt.Sprintf("%q matches several records, use an ID:\n%s", e.Query, strings.Join(lines, "\n"))
}

// Remote is the server API; *api.Client implements it.
type Remote interface {
	SetToken(token string)
	Register(ctx context.Context, login string, authKey []byte) (string, error)
	Login(ctx context.Context, login string, authKey []byte) (string, error)
	Upsert(ctx context.Context, id uuid.UUID, baseVersion int64, content api.Content) (api.Item, error)
	Delete(ctx context.Context, id uuid.UUID, baseVersion int64) (api.Item, error)
	Sync(ctx context.Context, since int64) ([]api.Item, int64, bool, error)
	Search(ctx context.Context, query string) ([]api.Item, bool, error)
	Close() error
}

// Config holds the dependencies of App.
type Config struct {
	DataDir string
	Dial    func(server string) (Remote, error)
	Derive  func(login, password string) (crypto.Keys, error) // crypto.Derive when nil
	Now     func() time.Time                                  // time.Now when nil
}

// Report summarizes a synchronization. Offline means the server was unreachable and changes stay local.
type Report struct {
	Pushed    int
	Pulled    int
	Conflicts int
	Offline   bool
}

// App is the client state of one data directory. It is not safe for concurrent use.
type App struct {
	cfg      Config
	session  store.Session
	loggedIn bool
	cache    *store.Cache
	remote   Remote
	encKey   []byte
}

// New loads the session and cache from cfg.DataDir.
func New(cfg Config) (*App, error) {
	if cfg.Derive == nil {
		cfg.Derive = crypto.Derive
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	a := &App{cfg: cfg}
	s, err := store.LoadSession(cfg.DataDir)
	switch {
	case errors.Is(err, store.ErrNoSession):
		return a, nil
	case err != nil:
		return nil, err
	}
	if a.cache, err = store.LoadCache(cfg.DataDir, s.Server, s.Login); err != nil {
		return nil, err
	}
	a.session, a.loggedIn = s, true
	return a, nil
}

// Close closes the server connection, if any.
func (a *App) Close() error {
	if a.remote == nil {
		return nil
	}
	err := a.remote.Close()
	a.remote = nil
	return err
}

// Session returns the current session and whether someone is logged in.
func (a *App) Session() (store.Session, bool) {
	return a.session, a.loggedIn
}

// Register creates an account on the server, logs in and synchronizes.
func (a *App) Register(ctx context.Context, server, login, password string) (Report, error) {
	if err := crypto.ValidatePassword(password); err != nil {
		return Report{}, err
	}
	return a.authenticate(ctx, server, login, password, Remote.Register)
}

// Login logs into an existing account and synchronizes. Logins are case-insensitive.
// The cache of another account is dropped, unless it has unsent changes: then ErrUnsentChanges is returned.
func (a *App) Login(ctx context.Context, server, login, password string) (Report, error) {
	return a.authenticate(ctx, server, login, password, Remote.Login)
}

type authFunc func(r Remote, ctx context.Context, login string, authKey []byte) (string, error)

func (a *App) authenticate(ctx context.Context, server, login, password string, call authFunc) (Report, error) {
	login = strings.ToLower(strings.TrimSpace(login))
	if a.loggedIn && (a.session.Server != server || a.session.Login != login) && a.Pending() > 0 {
		return Report{}, fmt.Errorf("%w: %d changes of %s are not sent yet, run sync first", ErrUnsentChanges, a.Pending(), a.session.Login)
	}
	keys, err := a.cfg.Derive(login, password)
	if err != nil {
		return Report{}, err
	}
	a.Close()
	remote, err := a.cfg.Dial(server)
	if err != nil {
		return Report{}, err
	}
	token, err := call(remote, ctx, login, keys.Auth)
	if err != nil {
		remote.Close()
		return Report{}, err
	}
	a.remote = remote
	check, err := crypto.Seal(keys.Enc, checkPlaintext, nil)
	if err != nil {
		return Report{}, err
	}

	revision := int64(0)
	if a.loggedIn && a.session.Server == server && a.session.Login == login {
		revision = a.session.Revision
	}
	a.session = store.Session{Server: server, Login: login, Token: token, Revision: revision, Check: check}
	a.loggedIn = true
	remote.SetToken(token)
	if a.cache, err = store.LoadCache(a.cfg.DataDir, server, login); err != nil {
		return Report{}, err
	}
	if len(a.cache.Entries) == 0 {
		a.session.Revision = 0
	}
	a.encKey = keys.Enc
	if err := a.save(); err != nil {
		return Report{}, err
	}
	return a.Sync(ctx)
}

// Logout forgets the session, the key and the cache.
func (a *App) Logout() error {
	a.Close()
	a.session, a.loggedIn, a.cache, a.encKey = store.Session{}, false, nil, nil
	return store.ClearSession(a.cfg.DataDir)
}

// Unlock derives the keys from the master password and checks it against the session.
func (a *App) Unlock(password string) error {
	if !a.loggedIn {
		return ErrNotLoggedIn
	}
	keys, err := a.cfg.Derive(a.session.Login, password)
	if err != nil {
		return err
	}
	if _, err := crypto.Open(keys.Enc, a.session.Check, nil); err != nil {
		return ErrWrongPassword
	}
	a.encKey = keys.Enc
	return nil
}

// Pending returns the number of local changes not yet sent to the server.
func (a *App) Pending() int {
	if a.cache == nil {
		return 0
	}
	return len(a.cache.Dirty())
}

// List returns the records of the kind, or of every kind when kind is empty, sorted by name.
func (a *App) List(kind vault.Kind) ([]vault.Record, error) {
	if err := a.requireKey(); err != nil {
		return nil, err
	}
	var out []vault.Record
	for id, e := range a.cache.Entries {
		if e.Deleted {
			continue
		}
		r, err := a.decrypt(id, sealedEntry(e))
		if err != nil {
			return nil, err
		}
		if kind == "" || r.Kind() == kind {
			out = append(out, r)
		}
	}
	sortRecords(out)
	return out, nil
}

// SearchResult is the outcome of Search. Partial means the server had more matches than fit one
// response; Offline means the server was unreachable and only the local cache was searched.
type SearchResult struct {
	Records []vault.Record
	Partial bool
	Offline bool
}

// Search returns the records whose name or meta contains query, ignoring case, sorted by name.
// The server does the filtering, so only matching records are downloaded and decrypted; local changes
// not sent yet take precedence. When the server is unreachable the local cache is searched instead.
func (a *App) Search(ctx context.Context, query string) (SearchResult, error) {
	if err := a.requireKey(); err != nil {
		return SearchResult{}, err
	}
	var res SearchResult
	var items []api.Item
	remote, err := a.connect()
	if err == nil {
		items, res.Partial, err = remote.Search(ctx, query)
	}
	if err != nil {
		if err = a.fail(err); !errors.Is(err, api.ErrUnavailable) {
			return SearchResult{}, err
		}
		res.Offline = true
	}

	found := make(map[uuid.UUID]vault.Sealed, len(items))
	for _, it := range items {
		found[it.ID] = vault.Sealed{Name: it.Name, Meta: it.Meta, Payload: it.Payload}
	}
	for id, e := range a.cache.Entries {
		if !res.Offline && !e.Dirty {
			continue
		}
		delete(found, id)
		if !e.Deleted && (containsFold(e.Name, query) || containsFold(e.Meta, query)) {
			found[id] = sealedEntry(e)
		}
	}
	for id, s := range found {
		r, err := a.decrypt(id, s)
		if err != nil {
			return SearchResult{}, err
		}
		res.Records = append(res.Records, r)
	}
	sortRecords(res.Records)
	return res, nil
}

func (a *App) decrypt(id uuid.UUID, s vault.Sealed) (vault.Record, error) {
	r, err := vault.Decrypt(id, s, a.encKey)
	if err != nil {
		return vault.Record{}, fmt.Errorf("decrypt %s: %w", id, err)
	}
	return r, nil
}

func sealedEntry(e store.Entry) vault.Sealed {
	return vault.Sealed{Name: e.Name, Meta: e.Meta, Payload: e.Payload}
}

func containsFold(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

func sortRecords(records []vault.Record) {
	slices.SortFunc(records, func(x, y vault.Record) int {
		if c := strings.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name)); c != 0 {
			return c
		}
		return strings.Compare(x.ID.String(), y.ID.String())
	})
}

// Get returns the record with the ID.
func (a *App) Get(id uuid.UUID) (vault.Record, error) {
	if err := a.requireKey(); err != nil {
		return vault.Record{}, err
	}
	e, ok := a.cache.Get(id)
	if !ok || e.Deleted {
		return vault.Record{}, ErrNotFound
	}
	return vault.Decrypt(id, sealedEntry(e), a.encKey)
}

// Find returns the record whose ID starts with query or whose name equals it.
// Several matches give *AmbiguousError.
func (a *App) Find(query string) (vault.Record, error) {
	records, err := a.List("")
	if err != nil {
		return vault.Record{}, err
	}
	prefix := strings.ToLower(query)
	var matches []vault.Record
	for _, r := range records {
		if r.Name == query || (prefix != "" && strings.HasPrefix(r.ID.String(), prefix)) {
			matches = append(matches, r)
		}
	}
	switch len(matches) {
	case 0:
		return vault.Record{}, ErrNotFound
	case 1:
		return matches[0], nil
	}
	return vault.Record{}, &AmbiguousError{Query: query, Matches: matches}
}

// Add stores a new record locally and synchronizes. When the server is unreachable the record stays
// local and the report has Offline set.
func (a *App) Add(ctx context.Context, r vault.Record) (Report, error) {
	if err := a.requireKey(); err != nil {
		return Report{}, err
	}
	if _, ok := a.cache.Get(r.ID); ok {
		return Report{}, fmt.Errorf("record %s already exists", r.ID)
	}
	sealed, err := vault.Encrypt(r, a.encKey)
	if err != nil {
		return Report{}, err
	}
	a.cache.Put(r.ID, store.Entry{Dirty: true, Name: sealed.Name, Meta: sealed.Meta, Payload: sealed.Payload})
	return a.commit(ctx)
}

// Update replaces an existing record locally and synchronizes, like Add.
func (a *App) Update(ctx context.Context, r vault.Record) (Report, error) {
	if err := a.requireKey(); err != nil {
		return Report{}, err
	}
	e, ok := a.cache.Get(r.ID)
	if !ok || e.Deleted {
		return Report{}, ErrNotFound
	}
	r.Touch()
	sealed, err := vault.Encrypt(r, a.encKey)
	if err != nil {
		return Report{}, err
	}
	e.Name, e.Meta, e.Payload, e.Dirty = sealed.Name, sealed.Meta, sealed.Payload, true
	a.cache.Put(r.ID, e)
	return a.commit(ctx)
}

// Delete removes a record locally and synchronizes, like Add.
func (a *App) Delete(ctx context.Context, id uuid.UUID) (Report, error) {
	if !a.loggedIn {
		return Report{}, ErrNotLoggedIn
	}
	e, ok := a.cache.Get(id)
	if !ok || e.Deleted {
		return Report{}, ErrNotFound
	}
	if e.Version == 0 {
		a.cache.Remove(id)
	} else {
		a.cache.Put(id, store.Entry{Version: e.Version, Revision: e.Revision, Deleted: true, Dirty: true})
	}
	return a.commit(ctx)
}

func (a *App) commit(ctx context.Context) (Report, error) {
	if err := a.cache.Save(); err != nil {
		return Report{}, err
	}
	rep, err := a.Sync(ctx)
	if errors.Is(err, api.ErrUnavailable) {
		return Report{Offline: true}, nil
	}
	return rep, err
}

func (a *App) requireKey() error {
	if !a.loggedIn {
		return ErrNotLoggedIn
	}
	if a.encKey == nil {
		return ErrLocked
	}
	return nil
}

func (a *App) connect() (Remote, error) {
	if a.remote != nil {
		return a.remote, nil
	}
	remote, err := a.cfg.Dial(a.session.Server)
	if err != nil {
		return nil, err
	}
	remote.SetToken(a.session.Token)
	a.remote = remote
	return remote, nil
}

func (a *App) save() error {
	if err := store.SaveSession(a.cfg.DataDir, a.session); err != nil {
		return err
	}
	return a.cache.Save()
}
