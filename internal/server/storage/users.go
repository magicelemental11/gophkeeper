package storage

import (
	"context"
	"errors"

	"github.com/jackc/pgerrcode"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Errors returned by the storage.
var (
	ErrLoginTaken = errors.New("login is already taken")
	ErrNotFound   = errors.New("not found")
)

// User is a registered account.
type User struct {
	ID       int64
	Login    string
	AuthHash string
}

// CreateUser inserts a user and returns its ID, or ErrLoginTaken if the login exists.
func (s *Storage) CreateUser(ctx context.Context, login, authHash string) (int64, error) {
	var id int64
	err := s.pool.QueryRow(ctx,
		`INSERT INTO users (login, auth_hash) VALUES ($1, $2) RETURNING id`, login, authHash).Scan(&id)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == pgerrcode.UniqueViolation {
		return 0, ErrLoginTaken
	}
	return id, err
}

// UserByLogin returns the user with the login, or ErrNotFound.
func (s *Storage) UserByLogin(ctx context.Context, login string) (User, error) {
	u := User{Login: login}
	err := s.pool.QueryRow(ctx, `SELECT id, auth_hash FROM users WHERE login = $1`, login).Scan(&u.ID, &u.AuthHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}
