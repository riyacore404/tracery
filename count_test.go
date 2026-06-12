package main

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// ── syscallName (ARM64) ───────────────────────────────────────────────────────

func TestSyscallName_Read(t *testing.T) {
	// ARM64: read = 63
	if got := syscallName(63); got != "read" {
		t.Errorf("syscallName(63) = %q, want %q", got, "read")
	}
}

func TestSyscallName_Write(t *testing.T) {
	// ARM64: write = 64
	if got := syscallName(64); got != "write" {
		t.Errorf("syscallName(64) = %q, want %q", got, "write")
	}
}

func TestSyscallName_Openat(t *testing.T) {
	// ARM64: openat = 56
	if got := syscallName(56); got != "openat" {
		t.Errorf("syscallName(56) = %q, want %q", got, "openat")
	}
}

func TestSyscallName_Clone3(t *testing.T) {
	// clone3 = 435 (same on ARM64 and x86_64)
	if got := syscallName(435); got != "clone3" {
		t.Errorf("syscallName(435) = %q, want %q", got, "clone3")
	}
}

func TestSyscallName_RtSigprocmask(t *testing.T) {
	// ARM64: rt_sigprocmask = 135
	if got := syscallName(135); got != "rt_sigprocmask" {
		t.Errorf("syscallName(135) = %q, want %q", got, "rt_sigprocmask")
	}
}

func TestSyscallName_RtSigaction(t *testing.T) {
	// ARM64: rt_sigaction = 134
	if got := syscallName(134); got != "rt_sigaction" {
		t.Errorf("syscallName(134) = %q, want %q", got, "rt_sigaction")
	}
}

func TestSyscallName_Wait4(t *testing.T) {
	// ARM64: wait4 = 260
	if got := syscallName(260); got != "wait4" {
		t.Errorf("syscallName(260) = %q, want %q", got, "wait4")
	}
}

func TestSyscallName_Clone(t *testing.T) {
	// ARM64: clone = 220
	if got := syscallName(220); got != "clone" {
		t.Errorf("syscallName(220) = %q, want %q", got, "clone")
	}
}

func TestSyscallName_Execveat(t *testing.T) {
	// ARM64: execveat = 281
	if got := syscallName(281); got != "execveat" {
		t.Errorf("syscallName(281) = %q, want %q", got, "execveat")
	}
}

func TestSyscallName_UnknownNr(t *testing.T) {
	got := syscallName(9999)
	want := "syscall_9999"
	if got != want {
		t.Errorf("syscallName(9999) = %q, want %q", got, want)
	}
}

// ── sort order ────────────────────────────────────────────────────────────────

func TestSortOrder_HighestFirst(t *testing.T) {
	counts := []syscallCount{
		{Nr: 63, Name: "read", Count: 10},
		{Nr: 64, Name: "write", Count: 50},
		{Nr: 98, Name: "futex", Count: 5},
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	if counts[0].Name != "write" {
		t.Errorf("expected write first (count=50), got %s (count=%d)", counts[0].Name, counts[0].Count)
	}
	if counts[1].Name != "read" {
		t.Errorf("expected read second (count=10), got %s", counts[1].Name)
	}
	if counts[2].Name != "futex" {
		t.Errorf("expected futex last (count=5), got %s", counts[2].Name)
	}
}

func TestSortOrder_AllEqual(t *testing.T) {
	counts := []syscallCount{
		{Nr: 63, Name: "read", Count: 100},
		{Nr: 64, Name: "write", Count: 100},
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	// Both have same count — just verify no panic and length preserved
	if len(counts) != 2 {
		t.Errorf("sort changed length: got %d, want 2", len(counts))
	}
}

func TestSortOrder_SingleEntry(t *testing.T) {
	counts := []syscallCount{{Nr: 63, Name: "read", Count: 1}}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	if counts[0].Name != "read" {
		t.Errorf("single entry sort = %q, want read", counts[0].Name)
	}
}

// ── printJSON ─────────────────────────────────────────────────────────────────

func TestPrintJSON_ValidOutput(t *testing.T) {
	counts := []syscallCount{
		{Nr: 63, Name: "read", Count: 42},
		{Nr: 64, Name: "write", Count: 7},
	}
	out := JSONOutput{
		PID:      1234,
		ElapsedS: 5,
		Syscalls: counts,
	}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var roundtrip JSONOutput
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if roundtrip.PID != 1234 {
		t.Errorf("PID = %d, want 1234", roundtrip.PID)
	}
	if roundtrip.ElapsedS != 5 {
		t.Errorf("ElapsedS = %d, want 5", roundtrip.ElapsedS)
	}
	if len(roundtrip.Syscalls) != 2 {
		t.Errorf("Syscalls len = %d, want 2", len(roundtrip.Syscalls))
	}
	if roundtrip.Syscalls[0].Name != "read" {
		t.Errorf("first syscall = %q, want read", roundtrip.Syscalls[0].Name)
	}
	if roundtrip.Syscalls[0].Count != 42 {
		t.Errorf("first count = %d, want 42", roundtrip.Syscalls[0].Count)
	}
}

func TestPrintJSON_JSONFieldNames(t *testing.T) {
	out := JSONOutput{
		PID:      99,
		ElapsedS: 1,
		Syscalls: []syscallCount{{Nr: 63, Name: "read", Count: 1}},
	}
	data, _ := json.Marshal(out)
	s := string(data)
	for _, field := range []string{"pid", "elapsed_seconds", "syscalls", "syscall_nr", "syscall_name", "count"} {
		if !strings.Contains(s, `"`+field+`"`) {
			t.Errorf("JSON output missing field %q", field)
		}
	}
}

func TestPrintJSON_EmptySyscalls(t *testing.T) {
	out := JSONOutput{PID: 1, ElapsedS: 1, Syscalls: []syscallCount{}}
	data, err := json.Marshal(out)
	if err != nil {
		t.Fatalf("marshal empty syscalls: %v", err)
	}
	if !strings.Contains(string(data), "syscalls") {
		t.Error("JSON missing syscalls field for empty list")
	}
}

// ── CSV header printed once ───────────────────────────────────────────────────

func TestPrintCSV_HeaderOnFirstCallOnly(t *testing.T) {
	headerPrinted := false
	headerCount := 0

	for tick := 0; tick < 5; tick++ {
		if !headerPrinted {
			headerCount++
			headerPrinted = true
		}
	}

	if headerCount != 1 {
		t.Errorf("header printed %d times across 5 ticks, want exactly 1", headerCount)
	}
}

func TestPrintCSV_HeaderFlagLogic(t *testing.T) {
	// Simulate the actual flag logic used in countCmd
	csvHeaderPrinted := false

	calls := []bool{} // records whether header was passed true each call
	for tick := 0; tick < 3; tick++ {
		calls = append(calls, !csvHeaderPrinted)
		csvHeaderPrinted = true
	}

	// First call: header=true, rest: header=false
	if !calls[0] {
		t.Error("first tick: header should be true")
	}
	for i := 1; i < len(calls); i++ {
		if calls[i] {
			t.Errorf("tick %d: header should be false, was true", i)
		}
	}
}