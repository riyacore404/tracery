package main

import (
	"strings"
	"testing"
)

// ── arm64SyscallNr map ────────────────────────────────────────────────────────

func TestArm64SyscallNr_Read(t *testing.T) {
	nr, ok := arm64SyscallNr["read"]
	if !ok {
		t.Fatal("read not in arm64SyscallNr")
	}
	if nr != 63 {
		t.Errorf("read = %d, want 63 (ARM64)", nr)
	}
}

func TestArm64SyscallNr_Write(t *testing.T) {
	nr, ok := arm64SyscallNr["write"]
	if !ok {
		t.Fatal("write not in arm64SyscallNr")
	}
	if nr != 64 {
		t.Errorf("write = %d, want 64 (ARM64)", nr)
	}
}

func TestArm64SyscallNr_Openat(t *testing.T) {
	nr, ok := arm64SyscallNr["openat"]
	if !ok {
		t.Fatal("openat not in arm64SyscallNr")
	}
	if nr != 56 {
		t.Errorf("openat = %d, want 56 (ARM64)", nr)
	}
}

func TestArm64SyscallNr_Mmap(t *testing.T) {
	nr, ok := arm64SyscallNr["mmap"]
	if !ok {
		t.Fatal("mmap not in arm64SyscallNr")
	}
	if nr != 222 {
		t.Errorf("mmap = %d, want 222 (ARM64)", nr)
	}
}

func TestArm64SyscallNr_Futex(t *testing.T) {
	nr, ok := arm64SyscallNr["futex"]
	if !ok {
		t.Fatal("futex not in arm64SyscallNr")
	}
	if nr != 98 {
		t.Errorf("futex = %d, want 98 (ARM64)", nr)
	}
}

func TestArm64SyscallNr_Clone3(t *testing.T) {
	nr, ok := arm64SyscallNr["clone3"]
	if !ok {
		t.Fatal("clone3 not in arm64SyscallNr")
	}
	if nr != 435 {
		t.Errorf("clone3 = %d, want 435", nr)
	}
}

// ── formatBucketRange ─────────────────────────────────────────────────────────

func TestFormatBucketRange_Zero(t *testing.T) {
	got := formatBucketRange(0)
	if got != "0 - 1ns" {
		t.Errorf("bucket 0 = %q, want %q", got, "0 - 1ns")
	}
}

func TestFormatBucketRange_Bucket1(t *testing.T) {
	got := formatBucketRange(1)
	if !strings.Contains(got, "ns") {
		t.Errorf("bucket 1 = %q, want ns range", got)
	}
}

func TestFormatBucketRange_MicrosecondRange(t *testing.T) {
	// bucket 11: 1024ns - 2048ns → 1.0µs - 2.0µs
	got := formatBucketRange(11)
	if !strings.Contains(got, "µs") {
		t.Errorf("bucket 11 = %q, expected µs range", got)
	}
}

func TestFormatBucketRange_MillisecondRange(t *testing.T) {
	// bucket 21: ~1ms - ~2ms
	got := formatBucketRange(21)
	if !strings.Contains(got, "ms") {
		t.Errorf("bucket 21 = %q, expected ms range", got)
	}
}

func TestFormatBucketRange_NeverEmpty(t *testing.T) {
	for i := 0; i < maxBuckets; i++ {
		got := formatBucketRange(i)
		if got == "" {
			t.Errorf("formatBucketRange(%d) returned empty string", i)
		}
	}
}

func TestFormatBucketRange_HasSeparator(t *testing.T) {
	for i := 1; i < maxBuckets; i++ {
		got := formatBucketRange(i)
		if !strings.Contains(got, " - ") {
			t.Errorf("formatBucketRange(%d) = %q, missing ' - ' separator", i, got)
		}
	}
}

// ── printHistogram smoke tests ────────────────────────────────────────────────

func TestPrintHistogram_EmptyBuckets(t *testing.T) {
	var buckets [maxBuckets]uint64
	printHistogram(buckets, "read", 1234, 5)
}

func TestPrintHistogram_SingleBucket(t *testing.T) {
	var buckets [maxBuckets]uint64
	buckets[10] = 42
	printHistogram(buckets, "write", 5678, 10)
}

func TestPrintHistogram_MultipleActiveBuckets(t *testing.T) {
	var buckets [maxBuckets]uint64
	buckets[8] = 100
	buckets[9] = 500
	buckets[10] = 250
	buckets[11] = 50
	printHistogram(buckets, "futex", 9999, 30)
}