// Package store keeps the client session and the encrypted item cache on disk.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/uuid"
)

// File names inside the data directory.
const (
	SessionFile = "session.json"
	CacheFile   = "vault.json"
)

// ErrNoSession is returned when nobody is logged in.
var ErrNoSession = errors.New("not logged in")

// Session is the logged-in account. Check is a value sealed with the encryption key, used to verify the
// master password offline.
type Session struct {
	Server   string `json:"server"`
	Login    string `json:"login"`
	Token    string `json:"token"`
	Revision int64  `json:"last_revision"`
	Check    []byte `json:"check"`
}

// LoadSession reads the session from dir, or returns ErrNoSession.
func LoadSession(dir string) (Session, error) {
	var s Session
	err := readJSON(filepath.Join(dir, SessionFile), &s)
	if errors.Is(err, fs.ErrNotExist) {
		return Session{}, ErrNoSession
	}
	return s, err
}

// SaveSession writes the session to dir.
func SaveSession(dir string, s Session) error {
	return writeJSON(dir, SessionFile, s)
}

// ClearSession removes the session and the cache from dir.
func ClearSession(dir string) error {
	for _, name := range []string{SessionFile, CacheFile} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// Entry is a cached item: the name and meta in plain text and the encrypted payload, as on the server.
// Dirty entries have local changes not yet sent to the server; Version is the server version the change
// is based on, 0 for a record the server has not seen.
type Entry struct {
	Version  int64  `json:"version"`
	Revision int64  `json:"revision"`
	Deleted  bool   `json:"deleted"`
	Dirty    bool   `json:"dirty"`
	Name     string `json:"name"`
	Meta     string `json:"meta"`
	Payload  []byte `json:"payload"`
}

// Cache maps item IDs to entries of one account.
type Cache struct {
	Server  string              `json:"server"`
	Login   string              `json:"login"`
	Entries map[uuid.UUID]Entry `json:"entries"`

	dir string
}

// LoadCache reads the cache of the account from dir. A missing cache, or one of another account,
// gives an empty cache.
func LoadCache(dir, server, login string) (*Cache, error) {
	c := &Cache{}
	err := readJSON(filepath.Join(dir, CacheFile), c)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil || c.Server != server || c.Login != login || c.Entries == nil {
		c = &Cache{Server: server, Login: login, Entries: map[uuid.UUID]Entry{}}
	}
	c.dir = dir
	return c, nil
}

// Save writes the cache atomically.
func (c *Cache) Save() error {
	return writeJSON(c.dir, CacheFile, c)
}

// Put stores the entry.
func (c *Cache) Put(id uuid.UUID, e Entry) {
	c.Entries[id] = e
}

// Get returns the entry.
func (c *Cache) Get(id uuid.UUID) (Entry, bool) {
	e, ok := c.Entries[id]
	return e, ok
}

// Remove deletes the entry.
func (c *Cache) Remove(id uuid.UUID) {
	delete(c.Entries, id)
}

// Dirty returns the IDs of entries with unsent changes in a stable order.
func (c *Cache) Dirty() []uuid.UUID {
	var ids []uuid.UUID
	for id, e := range c.Entries {
		if e.Dirty {
			ids = append(ids, id)
		}
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	return ids
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s is corrupted: %w", filepath.Base(path), err)
	}
	return nil
}

func writeJSON(dir, name string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeFileAtomic(dir, name, data)
}

func writeFileAtomic(dir, name string, data []byte) (err error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, name+".*.tmp")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			tmp.Close()
			os.Remove(tmp.Name())
		}
	}()
	if err = tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err = tmp.Write(data); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}
