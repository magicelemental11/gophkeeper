// Package crypto derives keys from the master password and encrypts records with AES-256-GCM.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters of the master key derivation.
const (
	ArgonTime    = 3
	ArgonMemory  = 64 * 1024
	ArgonThreads = 4
)

// KeySize is the size of every derived key.
const KeySize = 32

// MinPasswordLength is the minimum number of characters in a master password.
const MinPasswordLength = 8

// ErrDecrypt is returned when a ciphertext cannot be opened: wrong key, corrupted data or other additional data.
var ErrDecrypt = errors.New("decryption failed")

// Params are Argon2id cost parameters; Memory is in KiB.
type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

var defaultParams = Params{Time: ArgonTime, Memory: ArgonMemory, Threads: ArgonThreads}

// Keys are derived from the login and master password. Auth is sent to the server, Enc never leaves the client.
type Keys struct {
	Auth []byte
	Enc  []byte
}

// Derive computes Argon2id over the password with a salt bound to the case-insensitive login,
// then splits the master key into the auth and encryption keys with HKDF-SHA256.
func Derive(login, password string) (Keys, error) {
	return DeriveWith(defaultParams, login, password)
}

// DeriveWith is Derive with custom Argon2id parameters, for tests that cannot afford the default cost.
func DeriveWith(p Params, login, password string) (Keys, error) {
	salt := sha256.Sum256([]byte("gophkeeper:" + strings.ToLower(login)))
	master := argon2.IDKey([]byte(password), salt[:], p.Time, p.Memory, p.Threads, KeySize)
	var keys [2][]byte
	for i, info := range []string{"auth", "enc"} {
		k, err := hkdf.Key(sha256.New, master, nil, info, KeySize)
		if err != nil {
			return Keys{}, err
		}
		keys[i] = k
	}
	return Keys{Auth: keys[0], Enc: keys[1]}, nil
}

// ValidatePassword checks that a new master password is long enough.
func ValidatePassword(password string) error {
	if utf8.RuneCountInString(password) < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	return nil
}

// Seal encrypts plaintext with AES-256-GCM bound to ad. The random nonce is prepended to the result.
func Seal(key, plaintext, ad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, ad), nil
}

// Open decrypts a Seal result, or returns ErrDecrypt.
func Open(key, ciphertext, ad []byte) ([]byte, error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrDecrypt
	}
	n := aead.NonceSize()
	plain, err := aead.Open(nil, ciphertext[:n], ciphertext[n:], ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plain, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes", KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
