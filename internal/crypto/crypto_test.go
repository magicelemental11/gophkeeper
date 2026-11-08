package crypto

import (
	"bytes"
	"errors"
	"testing"
)

var fast = Params{Time: 1, Memory: 64, Threads: 1}

func TestDeriveDefault(t *testing.T) {
	k, err := Derive("alice", "correct horse")
	if err != nil || len(k.Auth) != KeySize || len(k.Enc) != KeySize {
		t.Fatalf("got %v, %v", k, err)
	}
}

func TestDeriveWith(t *testing.T) {
	a, err := DeriveWith(fast, "Alice", "password1")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := DeriveWith(fast, "alice", "password1")
	if !bytes.Equal(a.Auth, b.Auth) || !bytes.Equal(a.Enc, b.Enc) {
		t.Error("login case changed the keys")
	}
	if bytes.Equal(a.Auth, a.Enc) {
		t.Error("auth and enc keys are equal")
	}
	c, _ := DeriveWith(fast, "alice", "password2")
	d, _ := DeriveWith(fast, "bob", "password1")
	if bytes.Equal(a.Enc, c.Enc) || bytes.Equal(a.Enc, d.Enc) {
		t.Error("different input gave the same key")
	}
}

func TestValidatePassword(t *testing.T) {
	if err := ValidatePassword("1234567"); err == nil {
		t.Error("short password accepted")
	}
	if err := ValidatePassword("пароль12"); err != nil {
		t.Errorf("8 characters rejected: %v", err)
	}
}

func TestSealOpen(t *testing.T) {
	key := bytes.Repeat([]byte{7}, KeySize)
	ad := []byte("id-1")
	plain := []byte("secret")

	ct, err := Seal(key, plain, ad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, ct, ad)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("open: %q, %v", got, err)
	}
	ct2, _ := Seal(key, plain, ad)
	if bytes.Equal(ct, ct2) {
		t.Error("two seals gave the same ciphertext")
	}

	tampered := bytes.Clone(ct)
	tampered[len(tampered)-1] ^= 1
	otherKey := bytes.Repeat([]byte{8}, KeySize)
	cases := map[string]struct {
		key, ct, ad []byte
	}{
		"wrong key":   {otherKey, ct, ad},
		"tampered":    {key, tampered, ad},
		"other ad":    {key, ct, []byte("id-2")},
		"too short":   {key, ct[:10], ad},
		"empty input": {key, nil, ad},
	}
	for name, c := range cases {
		if _, err := Open(c.key, c.ct, c.ad); !errors.Is(err, ErrDecrypt) {
			t.Errorf("%s: %v", name, err)
		}
	}

	if _, err := Seal(key[:16], plain, ad); err == nil {
		t.Error("short key accepted by Seal")
	}
	if _, err := Open(key[:16], ct, ad); err == nil {
		t.Error("short key accepted by Open")
	}
}
