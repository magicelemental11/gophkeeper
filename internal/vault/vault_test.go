package vault

import (
	"bytes"
	"encoding/base32"
	"encoding/gob"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/magicelemental11/gophkeeper/internal/crypto"
)

var key = bytes.Repeat([]byte{3}, crypto.KeySize)

var otpSecret = base32.StdEncoding.EncodeToString([]byte("otp-key-01"))

func TestMain(m *testing.M) {
	RegisterTypes()
	os.Exit(m.Run())
}

func TestParseKind(t *testing.T) {
	for _, k := range Kinds {
		if got, err := ParseKind(string(k)); err != nil || got != k {
			t.Errorf("%s: %v, %v", k, got, err)
		}
	}
	if _, err := ParseKind("note"); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestValidate(t *testing.T) {
	validCard := Card{Number: "4111 1111 1111 1111", Holder: "IVAN IVANOV", Expiry: "12/30", CVV: "123"}
	withCard := func(f func(*Card)) Card {
		c := validCard
		f(&c)
		return c
	}
	tests := []struct {
		name string
		rec  Record
		ok   bool
	}{
		{"credentials", New("mail", "", Credentials{Login: "a", Password: "b"}), true},
		{"only password", New("mail", "", Credentials{Password: "b"}), true},
		{"empty credentials", New("mail", "", Credentials{}), false},
		{"text", New("note", "meta", Text{Content: "hi"}), true},
		{"empty name", New("", "", Text{}), false},
		{"long name", New(strings.Repeat("я", MaxNameLength+1), "", Text{}), false},
		{"max name", New(strings.Repeat("я", MaxNameLength), "", Text{}), true},
		{"no data", Record{Name: "x"}, false},
		{"binary at limit", New("bin", "", Binary{Content: make([]byte, MaxBinarySize)}), true},
		{"binary over limit", New("bin", "", Binary{Content: make([]byte, MaxBinarySize+1)}), false},
		{"card", New("card", "", validCard), true},
		{"card 4-digit cvv", New("card", "", withCard(func(c *Card) { c.CVV = "1234" })), true},
		{"card expired", New("card", "", withCard(func(c *Card) { c.Expiry = "01/20" })), true},
		{"card bad luhn", New("card", "", withCard(func(c *Card) { c.Number = "4111111111111112" })), false},
		{"card short", New("card", "", withCard(func(c *Card) { c.Number = "42" })), false},
		{"card letters", New("card", "", withCard(func(c *Card) { c.Number = "4111a11111111111" })), false},
		{"card month 13", New("card", "", withCard(func(c *Card) { c.Expiry = "13/30" })), false},
		{"card month 00", New("card", "", withCard(func(c *Card) { c.Expiry = "00/30" })), false},
		{"card bad expiry", New("card", "", withCard(func(c *Card) { c.Expiry = "1/30" })), false},
		{"card expiry no slash", New("card", "", withCard(func(c *Card) { c.Expiry = "1230" })), false},
		{"card expiry sign", New("card", "", withCard(func(c *Card) { c.Expiry = "+1/30" })), false},
		{"card short cvv", New("card", "", withCard(func(c *Card) { c.CVV = "12" })), false},
		{"card letter cvv", New("card", "", withCard(func(c *Card) { c.CVV = "12a" })), false},
		{"otp", New("otp", "", OTP{Secret: otpSecret}), true},
		{"otp bad secret", New("otp", "", OTP{Secret: "not base32!"}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.rec.Validate(); (err == nil) != tt.ok {
				t.Fatalf("Validate() = %v, want ok=%v", err, tt.ok)
			}
		})
	}
}

func TestCardNormalizedAndExpired(t *testing.T) {
	r := New("card", "", Card{Number: "4111 1111 1111 1111", Expiry: "10/26", CVV: "123"})
	c := r.Data.(Card)
	if c.Number != "4111111111111111" {
		t.Fatalf("number %q", c.Number)
	}
	if c.Expired(time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC)) {
		t.Error("expired during the expiry month")
	}
	if !c.Expired(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("not expired after the expiry month")
	}
	if (Card{Expiry: "bad"}).Expired(time.Now()) {
		t.Error("bad expiry reported as expired")
	}
}

func TestEncryptDecrypt(t *testing.T) {
	records := []Record{
		New("mail", "https://mail.example", Credentials{Login: "alice", Password: "pw"}),
		New("note", "", Text{Content: "привет"}),
		New("photo", "", Binary{FileName: "a.png", Content: []byte{0, 1, 2}}),
		New("card", "bank", Card{Number: "4111111111111111", Holder: "A", Expiry: "12/30", CVV: "123"}),
		New("totp", "", OTP{Secret: otpSecret, Issuer: "Example"}),
	}
	for _, r := range records {
		t.Run(string(r.Kind()), func(t *testing.T) {
			sealed, err := Encrypt(r, key)
			if err != nil {
				t.Fatal(err)
			}
			if sealed.Name != r.Name || sealed.Meta != r.Meta || bytes.Contains(sealed.Payload, []byte(r.Name)) {
				t.Fatalf("sealed: %+v", sealed)
			}
			got, err := Decrypt(r.ID, sealed, key)
			if err != nil {
				t.Fatal(err)
			}
			if !got.UpdatedAt.Equal(r.UpdatedAt) {
				t.Fatalf("time %v, want %v", got.UpdatedAt, r.UpdatedAt)
			}
			got.UpdatedAt = r.UpdatedAt
			if !reflect.DeepEqual(got, r) {
				t.Fatalf("got %+v, want %+v", got, r)
			}
			if _, err := Decrypt(uuid.New(), sealed, key); !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("other id: %v", err)
			}
			renamed := sealed
			renamed.Name += "x"
			if _, err := Decrypt(r.ID, renamed, key); !errors.Is(err, crypto.ErrDecrypt) {
				t.Fatalf("changed name: %v", err)
			}

		})
	}
}

func TestNameMetaBoundary(t *testing.T) {
	r := New("ab", "c", Text{Content: "x"})
	sealed, err := Encrypt(r, key)
	if err != nil {
		t.Fatal(err)
	}
	sealed.Name, sealed.Meta = "a", "bc"
	if _, err := Decrypt(r.ID, sealed, key); !errors.Is(err, crypto.ErrDecrypt) {
		t.Fatalf("got %v", err)
	}
}

func TestEncryptErrors(t *testing.T) {
	if _, err := Encrypt(Record{Name: "x"}, key); !errors.Is(err, ErrNoData) {
		t.Fatalf("no data: %v", err)
	}
	r := New("x", "", Text{})
	if _, err := Encrypt(r, key[:5]); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestBinaryAtLimitFitsServerPayload(t *testing.T) {
	r := New("big", "", Binary{FileName: "big.bin", Content: make([]byte, MaxBinarySize)})
	sealed, err := Encrypt(r, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(sealed.Payload) > 11<<20 {
		t.Fatalf("payload %d bytes exceeds the server limit", len(sealed.Payload))
	}
}

func TestReadBinaryFile(t *testing.T) {
	dir := t.TempDir()
	small := filepath.Join(dir, "small.bin")
	if err := os.WriteFile(small, []byte{1, 2, 3}, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := ReadBinaryFile(small)
	if err != nil || b.FileName != "small.bin" || !bytes.Equal(b.Content, []byte{1, 2, 3}) {
		t.Fatalf("small: %+v, %v", b, err)
	}

	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, MaxBinarySize+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBinaryFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("big: %v", err)
	}
	if _, err := ReadBinaryFile(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
}

func TestEncryptTooLarge(t *testing.T) {
	r := New("big", "", Text{Content: strings.Repeat("t", MaxPayloadSize)})
	if _, err := Encrypt(r, key); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("got %v", err)
	}
	r = New("big", strings.Repeat("m", MaxMetaSize+1), Text{Content: "t"})
	if _, err := Encrypt(r, key); err == nil || !strings.Contains(err.Error(), "meta") {
		t.Fatalf("meta: %v", err)
	}
}

func TestDecryptIDMismatch(t *testing.T) {
	r := New("x", "", Text{Content: "a"})
	other := uuid.New()
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(secret{ID: r.ID, Data: r.Data}); err != nil {
		t.Fatal(err)
	}
	payload, _ := crypto.Seal(key, buf.Bytes(), additionalData(other, "x", ""))
	if _, err := Decrypt(other, Sealed{Name: "x", Payload: payload}, key); !errors.Is(err, ErrIDMismatch) {
		t.Fatalf("got %v", err)
	}
	garbage, _ := crypto.Seal(key, []byte("not gob"), additionalData(other, "x", ""))
	if _, err := Decrypt(other, Sealed{Name: "x", Payload: garbage}, key); err == nil {
		t.Fatal("garbage decoded")
	}
}

func TestSetData(t *testing.T) {
	r := New("x", "", Text{Content: "a"})
	r.UpdatedAt = time.Time{}
	r.SetData(Card{Number: "4111 1111 1111 1111"})
	if r.Kind() != KindCard || r.Data.(Card).Number != "4111111111111111" || r.UpdatedAt.IsZero() {
		t.Fatalf("got %+v", r)
	}
	if (Record{}).Kind() != "" {
		t.Fatal("empty record has a kind")
	}
}

func TestOTPCodeRFC6238(t *testing.T) {
	b32 := func(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) }
	sha1Key := b32("12345678901234567890")
	sha256Key := b32("12345678901234567890123456789012")
	sha512Key := b32(strings.Repeat("1234567890", 6) + "1234")
	tests := []struct {
		secret, alg string
		at          int64
		want        string
	}{
		{sha1Key, "SHA1", 59, "94287082"},
		{sha1Key, "SHA1", 1111111109, "07081804"},
		{sha1Key, "SHA1", 1111111111, "14050471"},
		{sha1Key, "SHA1", 1234567890, "89005924"},
		{sha1Key, "SHA1", 2000000000, "69279037"},
		{sha1Key, "SHA1", 20000000000, "65353130"},
		{sha256Key, "SHA256", 59, "46119246"},
		{sha256Key, "SHA256", 1111111109, "68084774"},
		{sha512Key, "SHA512", 59, "90693936"},
		{sha512Key, "SHA512", 1111111109, "25091201"},
	}
	for _, tt := range tests {
		o := OTP{Secret: tt.secret, Algorithm: tt.alg, Digits: 8}
		code, _, err := o.Code(time.Unix(tt.at, 0))
		if err != nil || code != tt.want {
			t.Errorf("%s at %d: %s, %v; want %s", tt.alg, tt.at, code, err, tt.want)
		}
	}
}

func TestOTPDefaultsAndRemaining(t *testing.T) {
	o := OTP{Secret: "jbsw y3dp ehpk 3pxp"}
	code, left, err := o.Code(time.Unix(65, 0))
	if err != nil || len(code) != 6 || left != 25*time.Second {
		t.Fatalf("got %s, %v, %v", code, left, err)
	}
	for name, bad := range map[string]OTP{
		"digits": {Secret: otpSecret, Digits: 9},
		"period": {Secret: otpSecret, Period: -1},
		"alg":    {Secret: otpSecret, Algorithm: "MD5"},
		"secret": {Secret: ""},
	} {
		if _, _, err := bad.Code(time.Now()); err == nil {
			t.Errorf("%s: invalid OTP accepted", name)
		}
	}
}

func TestParseOTPURI(t *testing.T) {
	o, err := ParseOTPURI("otpauth://totp/Example:alice@example.com?secret=" + otpSecret + "&issuer=Example")
	want := OTP{Issuer: "Example", Account: "alice@example.com", Secret: otpSecret, Digits: 6, Period: 30, Algorithm: "SHA1"}
	if err != nil || o != want {
		t.Fatalf("got %+v, %v", o, err)
	}
	o, err = ParseOTPURI("otpauth://totp/Corp:bob?secret=" + otpSecret + "&digits=8&period=60&algorithm=sha256")
	want = OTP{Issuer: "Corp", Account: "bob", Secret: otpSecret, Digits: 8, Period: 60, Algorithm: "SHA256"}
	if err != nil || o != want {
		t.Fatalf("got %+v, %v", o, err)
	}
	o, err = ParseOTPURI("otpauth://totp/carol?secret=" + otpSecret)
	if err != nil || o.Account != "carol" || o.Issuer != "" {
		t.Fatalf("got %+v, %v", o, err)
	}
	for _, bad := range []string{
		"https://totp/x?secret=" + otpSecret,
		"otpauth://hotp/x?secret=" + otpSecret,
		"otpauth://totp/x?secret=1111",
		"otpauth://totp/x?secret=" + otpSecret + "&digits=six",
		"otpauth://totp/x?secret=" + otpSecret + "&period=0x",
		"otpauth://totp/x?secret=" + otpSecret + "&digits=4",
		"::not a uri",
	} {
		if _, err := ParseOTPURI(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
