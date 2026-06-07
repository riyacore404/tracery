package output

import "testing"

func TestResolveAddress_Found(t *testing.T) {
	regions := []MemRegion{
		{Start: 0x1000, End: 0x2000, Offset: 0, Path: "/usr/lib/libc.so.6"},
		{Start: 0x3000, End: 0x4000, Offset: 0x1000, Path: "/usr/bin/myapp"},
	}
	path, offset := ResolveAddress(0x1500, regions)
	if path != "/usr/lib/libc.so.6" {
		t.Errorf("expected libc.so.6, got %q", path)
	}
	if offset != 0x500 {
		t.Errorf("expected offset 0x500, got 0x%x", offset)
	}
}

func TestResolveAddress_NotFound(t *testing.T) {
	regions := []MemRegion{
		{Start: 0x1000, End: 0x2000, Offset: 0, Path: "/usr/lib/libc.so.6"},
	}
	path, _ := ResolveAddress(0x9999, regions)
	if path != "" {
		t.Errorf("expected empty path for unmapped address, got %q", path)
	}
}

func TestFormatAddress_WithMapping(t *testing.T) {
	regions := []MemRegion{
		{Start: 0x1000, End: 0x2000, Offset: 0, Path: "/usr/lib/libc.so.6"},
	}
	got := FormatAddress(0x1100, regions)
	want := "libc.so.6+0x100"
	if got != want {
		t.Errorf("FormatAddress = %q, want %q", got, want)
	}
}

func TestFormatAddress_NoMapping(t *testing.T) {
	got := FormatAddress(0xdeadbeef, nil)
	if got != "0xdeadbeef" {
		t.Errorf("FormatAddress = %q, want hex fallback", got)
	}
}

func TestResolveStack_StopsAtZero(t *testing.T) {
	regions := []MemRegion{
		{Start: 0x1000, End: 0x2000, Offset: 0, Path: "/usr/bin/app"},
	}
	addrs := []uint64{0x1100, 0x1200, 0, 0x1300}
	frames := ResolveStack(addrs, regions)
	if len(frames) != 2 {
		t.Errorf("expected 2 frames before zero, got %d", len(frames))
	}
}