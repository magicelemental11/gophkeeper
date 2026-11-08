// Package buildinfo holds the version, date and commit a binary was built from.
package buildinfo

import (
	"fmt"
	"io"
)

// Build values, set with -ldflags "-X github.com/magicelemental11/gophkeeper/internal/buildinfo.Version=...".
var (
	Version = "N/A"
	Date    = "N/A"
	Commit  = "N/A"
)

// Fprint writes the application name with its build version, date and commit to w.
func Fprint(w io.Writer, app string) {
	fmt.Fprintf(w, "%s\nBuild version: %s\nBuild date: %s\nBuild commit: %s\n", app, Version, Date, Commit)
}
