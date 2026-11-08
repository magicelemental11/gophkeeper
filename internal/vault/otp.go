package vault

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Default TOTP parameters, used when an OTP record leaves them empty.
const (
	DefaultOTPDigits    = 6
	DefaultOTPPeriod    = 30
	DefaultOTPAlgorithm = "SHA1"
)

// OTP is a TOTP (RFC 6238) generator. Secret is base32 as shown by most services.
type OTP struct {
	Issuer    string
	Account   string
	Secret    string
	Digits    int
	Period    int
	Algorithm string
}

// Kind returns KindOTP.
func (OTP) Kind() Kind { return KindOTP }

// WithDefaults fills empty parameters and normalizes the secret and algorithm.
func (o OTP) WithDefaults() OTP {
	o.Secret = strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(o.Secret))
	o.Algorithm = strings.ToUpper(o.Algorithm)
	if o.Digits == 0 {
		o.Digits = DefaultOTPDigits
	}
	if o.Period == 0 {
		o.Period = DefaultOTPPeriod
	}
	if o.Algorithm == "" {
		o.Algorithm = DefaultOTPAlgorithm
	}
	return o
}

// Validate checks the secret, digits, period and algorithm.
func (o OTP) Validate() error {
	o = o.WithDefaults()
	if _, err := o.key(); err != nil {
		return err
	}
	if o.Digits < 6 || o.Digits > 8 {
		return errors.New("OTP digits must be 6 to 8")
	}
	if o.Period <= 0 {
		return errors.New("OTP period must be positive")
	}
	if _, err := hashFunc(o.Algorithm); err != nil {
		return err
	}
	return nil
}

// Code returns the code valid at t and how long it stays valid.
func (o OTP) Code(t time.Time) (string, time.Duration, error) {
	o = o.WithDefaults()
	if err := o.Validate(); err != nil {
		return "", 0, err
	}
	key, _ := o.key()
	h, _ := hashFunc(o.Algorithm)
	period := int64(o.Period)
	counter := t.Unix() / period
	remaining := time.Duration(period-t.Unix()%period) * time.Second
	return hotp(h, key, uint64(counter), o.Digits), remaining, nil
}

func (o OTP) key() ([]byte, error) {
	secret := strings.TrimRight(o.Secret, "=")
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil || len(key) == 0 {
		return nil, errors.New("OTP secret must be base32")
	}
	return key, nil
}

func hashFunc(algorithm string) (func() hash.Hash, error) {
	switch algorithm {
	case "SHA1":
		return sha1.New, nil
	case "SHA256":
		return sha256.New, nil
	case "SHA512":
		return sha512.New, nil
	}
	return nil, fmt.Errorf("unsupported OTP algorithm %q", algorithm)
}

func hotp(h func() hash.Hash, key []byte, counter uint64, digits int) string {
	mac := hmac.New(h, key)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	mod := uint32(1)
	for range digits {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, value%mod)
}

// ParseOTPURI parses an otpauth://totp/ URI as encoded in QR codes.
func ParseOTPURI(uri string) (OTP, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return OTP{}, fmt.Errorf("parse OTP URI: %w", err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		return OTP{}, errors.New("OTP URI must start with otpauth://totp/")
	}
	q := u.Query()
	o := OTP{Secret: q.Get("secret"), Issuer: q.Get("issuer"), Algorithm: q.Get("algorithm")}
	label := strings.TrimPrefix(u.Path, "/")
	if issuer, account, ok := strings.Cut(label, ":"); ok {
		o.Account = strings.TrimSpace(account)
		if o.Issuer == "" {
			o.Issuer = issuer
		}
	} else {
		o.Account = label
	}
	for name, dst := range map[string]*int{"digits": &o.Digits, "period": &o.Period} {
		if v := q.Get(name); v != "" {
			if *dst, err = strconv.Atoi(v); err != nil {
				return OTP{}, fmt.Errorf("OTP %s must be a number", name)
			}
		}
	}
	o = o.WithDefaults()
	return o, o.Validate()
}
