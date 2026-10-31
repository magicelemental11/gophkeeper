// Package memstore is an in-memory store with the semantics of the PostgreSQL storage, for tests.
package memstore

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/server/storage"
)

type user struct {
	storage.User
	revision int64
	items    map[uuid.UUID]storage.Item
}

// Store keeps users and items in memory, safe for concurrent use.
// Err, when set, is returned by every method to simulate a storage failure.
type Store struct {
	mu      sync.Mutex
	users   map[int64]*user
	byLogin map[string]int64
	Err     error
}

// New returns an empty Store.
func New() *Store {
	return &Store{users: map[int64]*user{}, byLogin: map[string]int64{}}
}

// CreateUser adds a user, or returns storage.ErrLoginTaken.
func (s *Store) CreateUser(_ context.Context, login, authHash string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return 0, s.Err
	}
	if _, ok := s.byLogin[login]; ok {
		return 0, storage.ErrLoginTaken
	}
	id := int64(len(s.users) + 1)
	s.users[id] = &user{User: storage.User{ID: id, Login: login, AuthHash: authHash}, items: map[uuid.UUID]storage.Item{}}
	s.byLogin[login] = id
	return id, nil
}

// UserByLogin returns the user, or storage.ErrNotFound.
func (s *Store) UserByLogin(_ context.Context, login string) (storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Err != nil {
		return storage.User{}, s.Err
	}
	id, ok := s.byLogin[login]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return s.users[id].User, nil
}

// Upsert behaves like storage.Storage.Upsert.
func (s *Store) Upsert(_ context.Context, userID int64, id uuid.UUID, baseVersion int64, payload []byte) (storage.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.user(userID)
	if err != nil {
		return storage.Item{}, err
	}
	cur, ok := u.items[id]
	switch {
	case !ok && baseVersion != 0:
		return storage.Item{}, storage.ErrNotFound
	case ok && cur.Version != baseVersion:
		return storage.Item{}, &storage.ConflictError{Current: cur}
	}
	return u.put(storage.Item{ID: id, Version: cur.Version + 1, Payload: slices.Clone(payload)}), nil
}

// Delete behaves like storage.Storage.Delete.
func (s *Store) Delete(_ context.Context, userID int64, id uuid.UUID, baseVersion int64) (storage.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.user(userID)
	if err != nil {
		return storage.Item{}, err
	}
	cur, ok := u.items[id]
	switch {
	case !ok:
		return storage.Item{}, storage.ErrNotFound
	case cur.Deleted:
		return cur, nil
	case cur.Version != baseVersion:
		return storage.Item{}, &storage.ConflictError{Current: cur}
	}
	return u.put(storage.Item{ID: id, Version: cur.Version + 1, Deleted: true}), nil
}

// Get behaves like storage.Storage.Get.
func (s *Store) Get(_ context.Context, userID int64, id uuid.UUID) (storage.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.user(userID)
	if err != nil {
		return storage.Item{}, err
	}
	it, ok := u.items[id]
	if !ok {
		return storage.Item{}, storage.ErrNotFound
	}
	return it, nil
}

// ChangesSince behaves like storage.Storage.ChangesSince.
func (s *Store) ChangesSince(_ context.Context, userID int64, since int64, maxBytes int) (storage.Changes, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, err := s.user(userID)
	if err != nil {
		return storage.Changes{}, err
	}
	var (
		out   []storage.Item
		sizes []int
	)
	for _, it := range u.items {
		if it.Revision > since {
			out = append(out, it)
		}
	}
	slices.SortFunc(out, func(a, b storage.Item) int { return int(a.Revision - b.Revision) })
	for _, it := range out {
		sizes = append(sizes, len(it.Payload))
	}
	ch := storage.Changes{Items: out[:storage.PageLen(sizes, maxBytes)], Revision: u.revision}
	if len(ch.Items) < len(out) {
		ch.Revision, ch.More = ch.Items[len(ch.Items)-1].Revision, true
	}
	return ch, nil
}

func (s *Store) user(id int64) (*user, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	u, ok := s.users[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return u, nil
}

func (u *user) put(it storage.Item) storage.Item {
	u.revision++
	it.Revision = u.revision
	it.UpdatedAt = time.Now().UTC()
	u.items[it.ID] = it
	return it
}
