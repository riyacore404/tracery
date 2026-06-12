package main

import "testing"

// ── commaSep ─────────────────────────────────────────────────────────────────

func TestCommaSep_Zero(t *testing.T) {
	got := commaSep(0)
	if got != "0" {
		t.Errorf("commaSep(0) = %q, want %q", got, "0")
	}
}

func TestCommaSep_TwoDigits(t *testing.T) {
	got := commaSep(42)
	if got != "42" {
		t.Errorf("commaSep(42) = %q, want %q", got, "42")
	}
}

func TestCommaSep_Thousands(t *testing.T) {
	got := commaSep(1000)
	if got != "1,000" {
		t.Errorf("commaSep(1000) = %q, want %q", got, "1,000")
	}
}

func TestCommaSep_Millions(t *testing.T) {
	got := commaSep(1_000_000)
	if got != "1,000,000" {
		t.Errorf("commaSep(1000000) = %q, want %q", got, "1,000,000")
	}
}

func TestCommaSep_LargeNumber(t *testing.T) {
	got := commaSep(1_234_567_890)
	if got != "1,234,567,890" {
		t.Errorf("commaSep(1234567890) = %q, want %q", got, "1,234,567,890")
	}
}

func TestCommaSep_999(t *testing.T) {
	got := commaSep(999)
	if got != "999" {
		t.Errorf("commaSep(999) = %q, want %q", got, "999")
	}
}

func TestCommaSep_1001(t *testing.T) {
	got := commaSep(1001)
	if got != "1,001" {
		t.Errorf("commaSep(1001) = %q, want %q", got, "1,001")
	}
}