package main

import (
	"strings"
	"testing"
	"unsafe"
)

// ── struct size verification ──────────────────────────────────────────────────

func TestKernelEventSize(t *testing.T) {
	// Must be 80 bytes to match C struct layout on ARM64
	got := int(unsafe.Sizeof(kernelEvent{}))
	if got != 80 {
		t.Errorf("kernelEvent size = %d bytes, want 80 — struct padding mismatch with C", got)
	}
}

func TestKernelEventAddrOffset(t *testing.T) {
	// addr must be at offset 40 (after timestamp+pid+tid+type+comm+pad)
	var e kernelEvent
	base := uintptr(unsafe.Pointer(&e))
	addrOff := uintptr(unsafe.Pointer(&e.Addr)) - base
	if addrOff != 40 {
		t.Errorf("Addr offset = %d, want 40 — padding mismatch", addrOff)
	}
}

func TestKernelEventNextCommOffset(t *testing.T) {
	// NextComm must be at offset 64
	var e kernelEvent
	base := uintptr(unsafe.Pointer(&e))
	off := uintptr(unsafe.Pointer(&e.NextComm)) - base
	if off != 64 {
		t.Errorf("NextComm offset = %d, want 64", off)
	}
}

// ── parseComm ─────────────────────────────────────────────────────────────────

func TestParseComm_NullTerminated(t *testing.T) {
	var b [16]byte
	copy(b[:], "bash")
	got := parseComm(b)
	if got != "bash" {
		t.Errorf("parseComm = %q, want %q", got, "bash")
	}
}

func TestParseComm_Full16Bytes(t *testing.T) {
	var b [16]byte
	copy(b[:], "tracery-worker-1")
	got := parseComm(b)
	if len(got) != 16 {
		t.Errorf("parseComm full = %q (len %d), want 16 chars", got, len(got))
	}
}

func TestParseComm_Empty(t *testing.T) {
	var b [16]byte
	got := parseComm(b)
	if got != "" {
		t.Errorf("parseComm empty = %q, want empty string", got)
	}
}

func TestParseComm_SingleChar(t *testing.T) {
	var b [16]byte
	b[0] = 'a'
	got := parseComm(b)
	if got != "a" {
		t.Errorf("parseComm single = %q, want %q", got, "a")
	}
}

func TestParseComm_NoBadUnicode(t *testing.T) {
	// If parsing is correct, comm should never contain replacement chars
	var b [16]byte
	copy(b[:], "python3")
	got := parseComm(b)
	if strings.ContainsRune(got, '\uFFFD') {
		t.Errorf("parseComm produced replacement character: %q", got)
	}
}

// ── formatBytes ───────────────────────────────────────────────────────────────

func TestFormatBytes_Zero(t *testing.T) {
	got := formatBytes(0)
	if got != "heap resize" {
		t.Errorf("formatBytes(0) = %q, want %q", got, "heap resize")
	}
}

func TestFormatBytes_Bytes(t *testing.T) {
	got := formatBytes(512)
	if got != "512B" {
		t.Errorf("formatBytes(512) = %q, want %q", got, "512B")
	}
}

func TestFormatBytes_Kilobytes(t *testing.T) {
	got := formatBytes(4096)
	if !strings.Contains(got, "KB") {
		t.Errorf("formatBytes(4096) = %q, want KB suffix", got)
	}
}

func TestFormatBytes_ExactKB(t *testing.T) {
	got := formatBytes(1024)
	if got != "1.0KB" {
		t.Errorf("formatBytes(1024) = %q, want %q", got, "1.0KB")
	}
}

func TestFormatBytes_Megabytes(t *testing.T) {
	got := formatBytes(2 * 1024 * 1024)
	if !strings.Contains(got, "MB") {
		t.Errorf("formatBytes(2MB) = %q, want MB suffix", got)
	}
}

// ── printEvent filter logic ───────────────────────────────────────────────────

func TestPrintEvent_MemFilterHidesSchedEvents(t *testing.T) {
	e := &kernelEvent{Type: eventSchedSwitch, PrevPID: 1, NextPID: 2}
	printEvent(e, "mem") // must not panic, must not print sched line
}

func TestPrintEvent_SchedFilterHidesMemEvents(t *testing.T) {
	e := &kernelEvent{Type: eventMemMmap, PID: 1, Addr: 0x7f000000, Size: 4096}
	printEvent(e, "sched") // must not panic, must not print mem line
}

func TestPrintEvent_AllFilterShowsBoth(t *testing.T) {
	mem := &kernelEvent{Type: eventMemMmap, PID: 1, Size: 4096}
	sched := &kernelEvent{Type: eventSchedSwitch, PrevPID: 1, NextPID: 2}
	printEvent(mem, "all")
	printEvent(sched, "all")
}

func TestPrintEvent_UnknownTypeNoOutput(t *testing.T) {
	e := &kernelEvent{Type: 99, PID: 1}
	printEvent(e, "all") // must not panic
}

func TestPrintEvent_BrkEvent(t *testing.T) {
	e := &kernelEvent{Type: eventMemBrk, PID: 100, Addr: 0x600000, Size: 0}
	printEvent(e, "mem")
	printEvent(e, "all")
}

func TestPrintEvent_MunmapEvent(t *testing.T) {
	e := &kernelEvent{Type: eventMemMunmap, PID: 200, Addr: 0x7f000000, Size: 4096}
	printEvent(e, "mem")
}