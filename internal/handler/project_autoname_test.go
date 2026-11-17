package handler

import (
	"strings"
	"testing"
)

func TestFallbackProjectNameUsesFirstWords(t *testing.T) {
	got := fallbackProjectName("  Assess   the riana.co website for exposed admin panels and old certificates today  ")
	if got != "Assess the riana.co website for exposed" {
		t.Fatalf("unexpected fallback %q", got)
	}
	if fallbackProjectName("   ") != "New project" {
		t.Fatal("empty message must fall back to a generic name")
	}
}

func TestSanitizeProjectNameRejectsUnusableReplies(t *testing.T) {
	if name, ok := sanitizeProjectName("\"Riana Website Assessment\"\nextra text"); !ok || name != "Riana Website Assessment" {
		t.Fatalf("quoted first line not cleaned: %q %v", name, ok)
	}
	if _, ok := sanitizeProjectName("ok"); ok {
		t.Fatal("too-short reply must be rejected")
	}
	if _, ok := sanitizeProjectName(strings.Repeat("x", 200)); ok {
		t.Fatal("overlong reply must be rejected")
	}
}
