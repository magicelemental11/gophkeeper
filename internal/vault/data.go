package vault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/magicelemental11/gophkeeper/internal/luhn"
)

// MaxBinarySize is the largest binary content a record may hold.
const MaxBinarySize = 10 << 20

// MaxPayloadSize is the largest encrypted record the server accepts.
const MaxPayloadSize = 11 << 20

// Credentials is a login and password pair.
type Credentials struct {
	Login    string
	Password string
}

// Kind returns KindCredentials.
func (Credentials) Kind() Kind { return KindCredentials }

// Validate requires the login or the password.
func (c Credentials) Validate() error {
	if c.Login == "" && c.Password == "" {
		return errors.New("login and password must not both be empty")
	}
	return nil
}

// Text is arbitrary text.
type Text struct {
	Content string
}

// Kind returns KindText.
func (Text) Kind() Kind { return KindText }

// Validate accepts any text.
func (Text) Validate() error { return nil }

// Binary is arbitrary binary data with an optional original file name.
type Binary struct {
	FileName string
	Content  []byte
}

// Kind returns KindBinary.
func (Binary) Kind() Kind { return KindBinary }

// Validate limits the content to MaxBinarySize.
func (b Binary) Validate() error {
	if len(b.Content) > MaxBinarySize {
		return fmt.Errorf("binary data must be at most %d MiB", MaxBinarySize>>20)
	}
	return nil
}

// ReadBinaryFile loads the file as Binary named after it. A file over MaxBinarySize is refused before reading.
func ReadBinaryFile(path string) (Binary, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Binary{}, err
	}
	name := filepath.Base(path)
	if fi.Size() > MaxBinarySize {
		return Binary{}, fmt.Errorf("%s is larger than %d MiB", name, MaxBinarySize>>20)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return Binary{}, err
	}
	return Binary{FileName: name, Content: content}, nil
}

// Card is a bank card. Expiry has the MM/YY format.
type Card struct {
	Number string
	Holder string
	Expiry string
	CVV    string
}

// Kind returns KindCard.
func (Card) Kind() Kind { return KindCard }

// Validate checks the number length and Luhn checksum, the expiry format and the CVV.
// An expired card is valid.
func (c Card) Validate() error {
	number := NormalizeCardNumber(c.Number)
	if len(number) < 12 || len(number) > 19 || !luhn.Valid(number) {
		return errors.New("card number must be 12 to 19 digits with a valid checksum")
	}
	if _, err := expiryEnd(c.Expiry); err != nil {
		return err
	}
	if len(c.CVV) < 3 || len(c.CVV) > 4 || !digits(c.CVV) {
		return errors.New("CVV must be 3 or 4 digits")
	}
	return nil
}

// Expired reports whether the card expiry month ended before now.
func (c Card) Expired(now time.Time) bool {
	end, err := expiryEnd(c.Expiry)
	return err == nil && !now.Before(end)
}

// NormalizeCardNumber removes spaces from a card number.
func NormalizeCardNumber(number string) string {
	return strings.ReplaceAll(number, " ", "")
}

func expiryEnd(expiry string) (time.Time, error) {
	mm, yy, ok := strings.Cut(expiry, "/")
	month, errM := strconv.Atoi(mm)
	year, errY := strconv.Atoi(yy)
	if !ok || len(mm) != 2 || len(yy) != 2 || !digits(mm) || !digits(yy) || errM != nil || errY != nil || month < 1 || month > 12 {
		return time.Time{}, errors.New("expiry must be MM/YY with month 01 to 12")
	}
	return time.Date(2000+year, time.Month(month)+1, 1, 0, 0, 0, 0, time.UTC), nil
}

func digits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
