package main

import (
	"strings"
	"testing"
)

func TestVersionText(t *testing.T) {
	t.Parallel()

	prevVersion, prevCommit, prevBuildDate := version, commit, buildDate
	t.Cleanup(func() {
		version, commit, buildDate = prevVersion, prevCommit, prevBuildDate
	})

	version = "0.1.0"
	commit = "abc1234"
	buildDate = "2026-03-06T00:00:00Z"

	text := versionText()
	for _, want := range []string{
		"mamotama-center",
		"version=0.1.0",
		"commit=abc1234",
		"build_date=2026-03-06T00:00:00Z",
		"go=",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in version text: %q", want, text)
		}
	}
}
