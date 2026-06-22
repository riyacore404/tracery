package aggregator

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func encodeTestEvent(t *testing.T, e EventT) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.LittleEndian, e); err != nil {
		t.Fatalf("encoding test event: %v", err)
	}
	return buf.Bytes()
}

func TestParseUprobeEvent_PlainEntry(t *testing.T) {
	in := EventT{
		TimestampNs: 1000,
		PID:         42,
		TID:         42,
		ProbeID:     PROBE_ID_UPROBE_ENTRY,
		Comm:        [16]byte{'m', 'y', 's', 'v', 'c'},
	}
	binary.LittleEndian.PutUint64(in.Payload[0:8], 111)
	binary.LittleEndian.PutUint64(in.Payload[8:16], 222)

	ev, err := ParseUprobeEvent(encodeTestEvent(t, in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Label != "UPROBE" {
		t.Errorf("expected label UPROBE, got %s", ev.Label)
	}
	if ev.Fields["arg0"] != uint64(111) || ev.Fields["arg1"] != uint64(222) {
		t.Errorf("unexpected args: %+v", ev.Fields)
	}
}

func TestParseUprobeEvent_PairWithLatency(t *testing.T) {
	in := EventT{
		ProbeID:   PROBE_ID_UPROBE_PAIR,
		LatencyNs: 5_000_000,
		Retval:    0,
	}
	ev, err := ParseUprobeEvent(encodeTestEvent(t, in))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ev.Label != "UPROBE_PAIR" {
		t.Errorf("expected label UPROBE_PAIR, got %s", ev.Label)
	}
	if ev.Fields["latency_ns"] != uint64(5_000_000) {
		t.Errorf("expected latency_ns=5000000, got %+v", ev.Fields["latency_ns"])
	}
}

func TestParseUprobeEvent_TruncatedRaw(t *testing.T) {
	_, err := ParseUprobeEvent([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error parsing truncated event, got nil")
	}
}

func TestCString_NoNullTerminator(t *testing.T) {
	b := []byte{'a', 'b', 'c'}
	if got := cString(b); got != "abc" {
		t.Errorf("expected 'abc', got %q", got)
	}
}

func TestCString_EmbeddedNull(t *testing.T) {
	b := []byte{'a', 'b', 0, 'c'}
	if got := cString(b); got != "ab" {
		t.Errorf("expected 'ab', got %q", got)
	}
}