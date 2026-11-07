package app_test

import (
	"os"
	"testing"

	"github.com/magicelemental11/gophkeeper/internal/vault"
)

func TestMain(m *testing.M) {
	vault.RegisterTypes()
	os.Exit(m.Run())
}
