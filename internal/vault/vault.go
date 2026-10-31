// Package vault defines the plaintext records kept by the client, their validation and encryption.
package vault

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/crypto"
)

// Kind is the type of data a record holds.
type Kind string

// Record kinds.
const (
	KindCredentials Kind = "credentials"
	KindText        Kind = "text"
	KindBinary      Kind = "binary"
	KindCard        Kind = "card"
	KindOTP         Kind = "otp"
)

// Kinds lists every record kind.
var Kinds = []Kind{KindCredentials, KindText, KindBinary, KindCard, KindOTP}

// ParseKind returns the kind with the given name.
func ParseKind(s string) (Kind, error) {
	for _, k := range Kinds {
		if string(k) == s {
			return k, nil
		}
	}
	return "", fmt.Errorf("unknown kind %q", s)
}

// MaxNameLength is the maximum number of characters in a record name.
const MaxNameLength = 256

// Errors returned by the package.
var (
	ErrIDMismatch = errors.New("record id does not match the item id")
	ErrNoData     = errors.New("record has no data")
)

// Data is the typed content of a record: Credentials, Text, Binary, Card or OTP.
type Data interface {
	Kind() Kind
	Validate() error
}

// Record is a decrypted entry. Meta is free text such as a site, a bank or recovery codes.
type Record struct {
	ID        uuid.UUID
	Name      string
	Meta      string
	UpdatedAt time.Time
	Data      Data
}

func init() {
	gob.Register(Credentials{})
	gob.Register(Text{})
	gob.Register(Binary{})
	gob.Register(Card{})
	gob.Register(OTP{})
}

// New returns a record with a fresh ID holding the data. Card numbers are normalized.
func New(name, meta string, data Data) Record {
	return Record{ID: uuid.New(), Name: name, Meta: meta, UpdatedAt: time.Now().UTC(), Data: normalize(data)}
}

// SetData replaces the data and bumps UpdatedAt.
func (r *Record) SetData(data Data) {
	r.Data = normalize(data)
	r.Touch()
}

// Touch sets UpdatedAt to the current time.
func (r *Record) Touch() {
	r.UpdatedAt = time.Now().UTC()
}

// Kind returns the kind of the record data.
func (r Record) Kind() Kind {
	if r.Data == nil {
		return ""
	}
	return r.Data.Kind()
}

// Validate checks the name and the data.
func (r Record) Validate() error {
	if r.Name == "" {
		return errors.New("name must not be empty")
	}
	if utf8.RuneCountInString(r.Name) > MaxNameLength {
		return fmt.Errorf("name must be at most %d characters", MaxNameLength)
	}
	if r.Data == nil {
		return ErrNoData
	}
	return r.Data.Validate()
}

// Encrypt validates and serializes the whole record, then seals it with encKey bound to the record ID.
// The result must fit MaxPayloadSize.
func Encrypt(r Record, encKey []byte) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(r); err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	payload, err := crypto.Seal(encKey, buf.Bytes(), r.ID[:])
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxPayloadSize {
		return nil, fmt.Errorf("record is larger than %d MiB with metadata", MaxPayloadSize>>20)
	}
	return payload, nil
}

// Decrypt opens a payload of the item id and checks that the record inside carries the same ID.
func Decrypt(id uuid.UUID, payload, encKey []byte) (Record, error) {
	plain, err := crypto.Open(encKey, payload, id[:])
	if err != nil {
		return Record{}, err
	}
	var r Record
	if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&r); err != nil {
		return Record{}, fmt.Errorf("decode record: %w", err)
	}
	if r.ID != id {
		return Record{}, ErrIDMismatch
	}
	return r, nil
}

func normalize(data Data) Data {
	switch d := data.(type) {
	case Card:
		d.Number = NormalizeCardNumber(d.Number)
		return d
	case OTP:
		return d.WithDefaults()
	}
	return data
}
