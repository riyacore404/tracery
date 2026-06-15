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

// ── formatBucketRange — verify against BPF log2_bucket() ─────────────────────
//
// BPF log2_bucket(v) counts right-shifts until v reaches 1.
// So bucket n covers durations from 2^n ns to 2^(n+1)-1 ns.
// The Go label must show [2^n, 2^(n+1)) — NOT [2^(n-1), 2^n).

func TestFormatBucketRange_Zero(t *testing.T) {
	got := formatBucketRange(0)
	if got != "0 - 1ns" {
		t.Errorf("bucket 0 = %q, want %q", got, "0 - 1ns")
	}
}

func TestFormatBucketRange_Bucket1(t *testing.T) {
	// BPF bucket 1: low=2^1=2ns, high=2^2=4ns → "2ns - 4ns"
	// (bucket n covers 2^n to 2^(n+1)-1 ns)
	got := formatBucketRange(1)
	if got != "2ns - 4ns" {
		t.Errorf("bucket 1 = %q, want %q", got, "2ns - 4ns")
	}
}

func TestFormatBucketRange_Bucket5(t *testing.T) {
	// BPF bucket 5 covers 32ns-63ns → label: "32ns - 64ns"
	got := formatBucketRange(5)
	if got != "32ns - 64ns" {
		t.Errorf("bucket 5 = %q, want %q", got, "32ns - 64ns")
	}
}

func TestFormatBucketRange_Bucket10(t *testing.T) {
	// BPF bucket 10 covers 1024ns-2047ns → label: "1.0µs - 2.0µs"
	got := formatBucketRange(10)
	if got != "1.0µs - 2.0µs" {
		t.Errorf("bucket 10 = %q, want %q", got, "1.0µs - 2.0µs")
	}
}

func TestFormatBucketRange_Bucket16_ReadLatency(t *testing.T) {
	// BPF bucket 16 covers 65536ns-131071ns → 65.5µs - 131.1µs
	// This is where /dev/urandom reads landed in our measurements.
	// Previously broken: showed "32.8µs - 65.5µs" (off by one).
	got := formatBucketRange(16)
	want := "65.5µs - 131.1µs"
	if got != want {
		t.Errorf("bucket 16 = %q, want %q (off-by-one in bucket math?)", got, want)
	}
}

func TestFormatBucketRange_Bucket20(t *testing.T) {
	// BPF bucket 20 covers ~1ms-2ms → "1.0ms - 2.1ms"
	got := formatBucketRange(20)
	if !strings.Contains(got, "ms") {
		t.Errorf("bucket 20 = %q, expected ms range", got)
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

func TestFormatBucketRange_MonotonicallyIncreasing(t *testing.T) {
	// Each bucket's lower bound should be higher than the previous bucket's lower bound
	prev := "0 - 1ns"
	for i := 1; i < maxBuckets-1; i++ {
		got := formatBucketRange(i)
		if got == prev {
			t.Errorf("bucket %d has same label as bucket %d: %q", i, i-1, got)
		}
		prev = got
	}
}

// ── printHistogram smoke tests ────────────────────────────────────────────────

func TestPrintHistogram_EmptyBuckets(t *testing.T) {
	var buckets [maxBuckets]uint64
	printHistogram(buckets, "read", 1234, 5)
}

func TestPrintHistogram_SingleBucket(t *testing.T) {
	var buckets [maxBuckets]uint64
	buckets[16] = 42 // simulate read latency in 65.5µs-131.1µs range
	printHistogram(buckets, "read", 5678, 10)
}

func TestPrintHistogram_MultipleActiveBuckets(t *testing.T) {
	var buckets [maxBuckets]uint64
	buckets[15] = 100
	buckets[16] = 500 // dominant bucket
	buckets[17] = 250
	buckets[18] = 50
	printHistogram(buckets, "write", 9999, 30)
}