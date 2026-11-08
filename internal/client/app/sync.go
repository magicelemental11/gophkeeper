package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/client/api"
	"github.com/magicelemental11/gophkeeper/internal/client/store"
	"github.com/magicelemental11/gophkeeper/internal/vault"
)

const conflictTimeFormat = "2006-01-02 15:04"

// Sync sends local changes, then fetches the changes made since the last synchronization.
// On a version conflict the server version wins and the local version is kept as a new record named
// "<name> (conflict <time>)". A conflicting local deletion is dropped.
func (a *App) Sync(ctx context.Context) (Report, error) {
	if !a.loggedIn {
		return Report{}, ErrNotLoggedIn
	}
	remote, err := a.connect()
	if err != nil {
		return Report{}, err
	}
	var rep Report
	for _, id := range a.cache.Dirty() {
		if err := a.push(ctx, remote, id, &rep); err != nil {
			return rep, a.fail(err)
		}
	}
	for {
		items, revision, more, err := remote.Sync(ctx, a.session.Revision)
		if err != nil {
			return rep, a.fail(err)
		}
		for _, it := range items {
			a.pull(it, &rep)
		}
		a.session.Revision = revision
		if !more {
			return rep, a.save()
		}
	}
}

func (a *App) fail(err error) error {
	if saveErr := a.save(); saveErr != nil {
		return errors.Join(err, saveErr)
	}
	switch {
	case errors.Is(err, api.ErrUnauthenticated):
		return ErrSessionExpired
	case errors.Is(err, api.ErrUnavailable):
		a.Close()
	}
	return err
}

func (a *App) push(ctx context.Context, remote Remote, id uuid.UUID, rep *Report) error {
	e, _ := a.cache.Get(id)
	var conflict *api.ConflictError

	if e.Deleted {
		it, err := remote.Delete(ctx, id, e.Version)
		switch {
		case errors.As(err, &conflict):
			a.store(conflict.Current)
			rep.Conflicts++
			return nil
		case errors.Is(err, api.ErrNotFound):
			a.cache.Remove(id)
			return nil
		case err != nil:
			return err
		}
		a.store(it)
		rep.Pushed++
		return nil
	}

	content := api.Content{Name: e.Name, Meta: e.Meta, Payload: e.Payload}
	it, err := remote.Upsert(ctx, id, e.Version, content)
	if errors.Is(err, api.ErrNotFound) {
		it, err = remote.Upsert(ctx, id, 0, content)
	}
	if errors.As(err, &conflict) {
		return a.resolve(ctx, remote, id, e, conflict.Current, rep)
	}
	if err != nil {
		return err
	}
	a.store(it)
	rep.Pushed++
	return nil
}

func (a *App) resolve(ctx context.Context, remote Remote, id uuid.UUID, local store.Entry, current api.Item, rep *Report) error {
	if a.encKey == nil {
		return ErrLocked
	}
	r, err := vault.Decrypt(id, sealedEntry(local), a.encKey)
	if err != nil {
		return fmt.Errorf("decrypt local copy of %s: %w", id, err)
	}
	a.store(current)
	rep.Conflicts++

	r.ID = uuid.New()
	r.Name = conflictName(r.Name, a.cfg.Now().Format(conflictTimeFormat))
	r.Touch()
	sealed, err := vault.Encrypt(r, a.encKey)
	if err != nil {
		return err
	}
	a.cache.Put(r.ID, store.Entry{Dirty: true, Name: sealed.Name, Meta: sealed.Meta, Payload: sealed.Payload})
	it, err := remote.Upsert(ctx, r.ID, 0, api.Content{Name: sealed.Name, Meta: sealed.Meta, Payload: sealed.Payload})
	if err != nil {
		return err
	}
	a.store(it)
	rep.Pushed++
	return nil
}

func (a *App) pull(it api.Item, rep *Report) {
	local, ok := a.cache.Get(it.ID)
	if ok && local.Dirty {
		return
	}
	if (ok && local.Version == it.Version) || (!ok && it.Deleted) {
		return
	}
	a.store(it)
	rep.Pulled++
}

func (a *App) store(it api.Item) {
	if it.Deleted {
		a.cache.Remove(it.ID)
		return
	}
	a.cache.Put(it.ID, store.Entry{Version: it.Version, Revision: it.Revision, Name: it.Name, Meta: it.Meta, Payload: it.Payload})
}

func conflictName(name, when string) string {
	suffix := fmt.Sprintf(" (conflict %s)", when)
	runes := []rune(name)
	if limit := vault.MaxNameLength - len([]rune(suffix)); len(runes) > limit {
		runes = runes[:limit]
	}
	return string(runes) + suffix
}
