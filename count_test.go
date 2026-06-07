package main

import "testing"

func TestSyscallName_KnownNr(t *testing.T) {
	if got := syscallName(63); got != "read" {
		t.Errorf("syscallName(63) = %q, want %q", got, "read")
	}
}

func TestSyscallName_UnknownNr(t *testing.T) {
	got := syscallName(9999)
	want := "syscall_9999"
	if got != want {
		t.Errorf("syscallName(9999) = %q, want %q", got, want)
	}
}

func TestFormatBucketRange_Zero(t *testing.T) {
	got := formatBucketRange(0)
	if got != "0 - 1ns" {
		t.Errorf("formatBucketRange(0) = %q, want %q", got, "0 - 1ns")
	}
}

func TestFormatBucketRange_Microseconds(t *testing.T) {
	// bucket 10 = 512ns-1024ns range
	got := formatBucketRange(10)
	if got == "" {
		t.Error("formatBucketRange(10) returned empty string")
	}
}

func TestSortOrder(t *testing.T) {
	counts := []syscallCount{
		{Nr: 63, Name: "read", Count: 10},
		{Nr: 64, Name: "write", Count: 50},
		{Nr: 98, Name: "futex", Count: 5},
	}
	// Simulate the sort from readCounts
	for i := 0; i < len(counts)-1; i++ {
		for j := i + 1; j < len(counts); j++ {
			if counts[i].Count < counts[j].Count {
				counts[i], counts[j] = counts[j], counts[i]
			}
		}
	}
	if counts[0].Name != "write" {
		t.Errorf("expected write first, got %s", counts[0].Name)
	}
	if counts[2].Name != "futex" {
		t.Errorf("expected futex last, got %s", counts[2].Name)
	}
}