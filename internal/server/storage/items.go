package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Item is an encrypted record of a user. A deleted item (tombstone) has a nil payload.
type Item struct {
	ID        uuid.UUID
	Version   int64
	Revision  int64
	Deleted   bool
	Payload   []byte
	UpdatedAt time.Time
}

// ConflictError is returned when the base version of a change differs from the stored one.
type ConflictError struct {
	Current Item
}

// Error describes the conflicting item and its current version.
func (e *ConflictError) Error() string {
	return fmt.Sprintf("version conflict: item %s is at version %d", e.Current.ID, e.Current.Version)
}

const itemColumns = `id, version, revision, deleted, payload, updated_at`

func scanItem(row pgx.Row) (Item, error) {
	var it Item
	err := row.Scan(&it.ID, &it.Version, &it.Revision, &it.Deleted, &it.Payload, &it.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	return it, err
}

// Upsert creates the item when baseVersion is 0 and it does not exist, or replaces it when baseVersion
// equals the stored version; a tombstone is restored this way. A version mismatch returns *ConflictError,
// a nonzero baseVersion for a missing item returns ErrNotFound.
func (s *Storage) Upsert(ctx context.Context, userID int64, id uuid.UUID, baseVersion int64, payload []byte) (Item, error) {
	return s.write(ctx, userID, id, func(tx pgx.Tx, cur *Item, revision int64) (Item, bool, error) {
		if cur == nil {
			if baseVersion != 0 {
				return Item{}, false, ErrNotFound
			}
			it, err := scanItem(tx.QueryRow(ctx,
				`INSERT INTO items (id, user_id, version, revision, payload) VALUES ($1, $2, 1, $3, $4)
				 RETURNING `+itemColumns, id, userID, revision, payload))
			return it, true, err
		}
		if cur.Version != baseVersion {
			return Item{}, false, &ConflictError{Current: *cur}
		}
		it, err := scanItem(tx.QueryRow(ctx,
			`UPDATE items SET version = version + 1, revision = $3, deleted = false, payload = $4, updated_at = now()
			 WHERE user_id = $1 AND id = $2 RETURNING `+itemColumns, userID, id, revision, payload))
		return it, true, err
	})
}

// Delete turns the item into a tombstone with the same version checks as Upsert.
// Deleting a tombstone again succeeds without changes.
func (s *Storage) Delete(ctx context.Context, userID int64, id uuid.UUID, baseVersion int64) (Item, error) {
	return s.write(ctx, userID, id, func(tx pgx.Tx, cur *Item, revision int64) (Item, bool, error) {
		switch {
		case cur == nil:
			return Item{}, false, ErrNotFound
		case cur.Deleted:
			return *cur, false, nil
		case cur.Version != baseVersion:
			return Item{}, false, &ConflictError{Current: *cur}
		}
		it, err := scanItem(tx.QueryRow(ctx,
			`UPDATE items SET version = version + 1, revision = $3, deleted = true, payload = NULL, updated_at = now()
			 WHERE user_id = $1 AND id = $2 RETURNING `+itemColumns, userID, id, revision))
		return it, true, err
	})
}

type writeFunc func(tx pgx.Tx, cur *Item, revision int64) (it Item, changed bool, err error)

func (s *Storage) write(ctx context.Context, userID int64, id uuid.UUID, apply writeFunc) (Item, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Item{}, err
	}
	defer tx.Rollback(ctx)

	var revision int64
	err = tx.QueryRow(ctx, `UPDATE users SET revision = revision + 1 WHERE id = $1 RETURNING revision`, userID).Scan(&revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return Item{}, ErrNotFound
	}
	if err != nil {
		return Item{}, err
	}

	var cur *Item
	it, err := scanItem(tx.QueryRow(ctx,
		`SELECT `+itemColumns+` FROM items WHERE user_id = $1 AND id = $2 FOR UPDATE`, userID, id))
	switch {
	case err == nil:
		cur = &it
	case !errors.Is(err, ErrNotFound):
		return Item{}, err
	}

	it, changed, err := apply(tx, cur, revision)
	if err != nil || !changed {
		return it, err
	}
	return it, tx.Commit(ctx)
}

// Get returns the item, including a tombstone, or ErrNotFound.
func (s *Storage) Get(ctx context.Context, userID int64, id uuid.UUID) (Item, error) {
	return scanItem(s.pool.QueryRow(ctx, `SELECT `+itemColumns+` FROM items WHERE user_id = $1 AND id = $2`, userID, id))
}

// Changes is one page of the items changed after a revision. Revision is where the next page starts:
// the revision of the last item when More is set, otherwise the current revision of the user.
type Changes struct {
	Items    []Item
	Revision int64
	More     bool
}

// PageLen returns how many leading items with the given payload sizes fit maxBytes together, at least one.
func PageLen(sizes []int, maxBytes int) int {
	total := 0
	for i, size := range sizes {
		total += size
		if i > 0 && total > maxBytes {
			return i
		}
	}
	return len(sizes)
}

// ChangesSince returns the items changed after the revision in revision order, as many as fit maxBytes
// of payload, read from one snapshot. Payloads past the page are not loaded.
func (s *Storage) ChangesSince(ctx context.Context, userID int64, since int64, maxBytes int) (Changes, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Changes{}, err
	}
	defer tx.Rollback(ctx)

	var ch Changes
	if err := tx.QueryRow(ctx, `SELECT revision FROM users WHERE id = $1`, userID).Scan(&ch.Revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Changes{}, ErrNotFound
		}
		return Changes{}, err
	}

	rows, err := tx.Query(ctx,
		`SELECT revision, coalesce(octet_length(payload), 0) FROM items WHERE user_id = $1 AND revision > $2 ORDER BY revision`,
		userID, since)
	if err != nil {
		return Changes{}, err
	}
	var (
		revisions []int64
		sizes     []int
		revision  int64
		size      int
	)
	_, err = pgx.ForEachRow(rows, []any{&revision, &size}, func() error {
		revisions = append(revisions, revision)
		sizes = append(sizes, size)
		return nil
	})
	if err != nil || len(revisions) == 0 {
		return ch, err
	}

	n := PageLen(sizes, maxBytes)
	last := revisions[n-1]
	rows, err = tx.Query(ctx,
		`SELECT `+itemColumns+` FROM items WHERE user_id = $1 AND revision > $2 AND revision <= $3 ORDER BY revision`,
		userID, since, last)
	if err != nil {
		return Changes{}, err
	}
	ch.Items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Item, error) { return scanItem(row) })
	if err != nil {
		return Changes{}, err
	}
	if n < len(revisions) {
		ch.Revision, ch.More = last, true
	}
	return ch, tx.Commit(ctx)
}
