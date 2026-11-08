// Package vault defines the plaintext records kept by the client, their validation and encryption.
package vault

import (
	"bytes"
	"encoding/binary"
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

// MaxMetaSize is the maximum size of the record meta information in bytes.
const MaxMetaSize = 64 << 10

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
// Name and Meta are stored in plain text so the server can search by them; the rest is encrypted.
type Record struct {
	ID        uuid.UUID
	Name      string
	Meta      string
	UpdatedAt time.Time
	Data      Data
}

// Sealed is an encrypted record as stored on the server and in the local cache.
// Name and Meta are bound to the payload, so changing them breaks decryption.
type Sealed struct {
	Name    string
	Meta    string
	Payload []byte
}

type secret struct {
	ID        uuid.UUID
	UpdatedAt time.Time
	Data      Data
}

// RegisterTypes registers the Data implementations with encoding/gob. It must be called once before
// Encrypt or Decrypt.
func RegisterTypes() {
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
	if len(r.Meta) > MaxMetaSize {
		return fmt.Errorf("meta must be at most %d KiB", MaxMetaSize>>10)
	}
	if r.Data == nil {
		return ErrNoData
	}
	return r.Data.Validate()
}

// Encrypt validates the record and seals everything except the name and meta with encKey, binding
// the ciphertext to the record ID, name and meta. The payload must fit MaxPayloadSize.
func Encrypt(r Record, encKey []byte) (Sealed, error) {
	if err := r.Validate(); err != nil {
		return Sealed{}, err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(secret{ID: r.ID, UpdatedAt: r.UpdatedAt, Data: r.Data}); err != nil {
		return Sealed{}, fmt.Errorf("encode record: %w", err)
	}
	payload, err := crypto.Seal(encKey, buf.Bytes(), additionalData(r.ID, r.Name, r.Meta))
	if err != nil {
		return Sealed{}, err
	}
	if len(payload) > MaxPayloadSize {
		return Sealed{}, fmt.Errorf("record is larger than %d MiB", MaxPayloadSize>>20)
	}
	return Sealed{Name: r.Name, Meta: r.Meta, Payload: payload}, nil
}

// Decrypt opens a sealed record of the item id and checks that the record inside carries the same ID.
func Decrypt(id uuid.UUID, s Sealed, encKey []byte) (Record, error) {
	plain, err := crypto.Open(encKey, s.Payload, additionalData(id, s.Name, s.Meta))
	if err != nil {
		return Record{}, err
	}
	var sec secret
	if err := gob.NewDecoder(bytes.NewReader(plain)).Decode(&sec); err != nil {
		return Record{}, fmt.Errorf("decode record: %w", err)
	}
	if sec.ID != id {
		return Record{}, ErrIDMismatch
	}
	return Record{ID: id, Name: s.Name, Meta: s.Meta, UpdatedAt: sec.UpdatedAt, Data: sec.Data}, nil
}

func additionalData(id uuid.UUID, name, meta string) []byte {
	ad := make([]byte, 0, len(id)+4+len(name)+len(meta))
	ad = append(ad, id[:]...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(name)))
	ad = append(ad, name...)
	return append(ad, meta...)
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
