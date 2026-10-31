package buildinfo

import (
	"bytes"
	"testing"
)

func TestFprint(t *testing.T) {
	var buf bytes.Buffer
	Fprint(&buf, "gophkeeper")
	want := "gophkeeper\nBuild version: N/A\nBuild date: N/A\nBuild commit: N/A\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}

	Version, Date, Commit = "v1.0.0", "2026-10-31T12:00:00Z", "abc1234"
	t.Cleanup(func() { Version, Date, Commit = "N/A", "N/A", "N/A" })
	buf.Reset()
	Fprint(&buf, "server")
	want = "server\nBuild version: v1.0.0\nBuild date: 2026-10-31T12:00:00Z\nBuild commit: abc1234\n"
	if buf.String() != want {
		t.Fatalf("got %q, want %q", buf.String(), want)
	}
}
