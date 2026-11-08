package tui

import (
	"encoding/base32"
	"os"
	"testing"

	"github.com/magicelemental11/gophkeeper/internal/vault"
)

func TestMain(m *testing.M) {
	vault.RegisterTypes()
	os.Exit(m.Run())
}

var otpSecret = base32.StdEncoding.EncodeToString([]byte("otp-key-01"))
