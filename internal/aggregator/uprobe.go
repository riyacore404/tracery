package aggregator

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// EventT mirrors bpf/uprobe.bpf.c's struct uprobe_event_t exactly — both
// sides are tightly packed (no struct padding), so field order and sizes
// must match byte-for-byte.
type EventT struct {
	TimestampNs uint64
	PID         uint32
	TID         uint32
	SyscallNr   uint32
	Retval      int64
	LatencyNs   uint64
	ProbeID     uint32
	Comm        [16]byte
	Payload     [64]byte
}

// ParseUprobeEvent decodes a raw ring buffer record produced by
// bpf/uprobe.bpf.c into a normalized Event.
func ParseUprobeEvent(raw []byte) (Event, error) {
	var e EventT
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return Event{}, fmt.Errorf("parsing uprobe event: %w", err)
	}

	label := "UPROBE"
	switch e.ProbeID {
	case PROBE_ID_UPROBE_PAIR:
		label = "UPROBE_PAIR"
	case PROBE_ID_URETPROBE:
		label = "URETPROBE"
	}

	fields := map[string]any{
		"comm": cString(e.Comm[:]),
	}
	if e.LatencyNs > 0 {
		fields["latency_ns"] = e.LatencyNs
	}
	if e.Retval != 0 {
		fields["retval"] = e.Retval
	}
	if label == "UPROBE" {
		var arg0, arg1 uint64
		_ = binary.Read(bytes.NewReader(e.Payload[0:8]), binary.LittleEndian, &arg0)
		_ = binary.Read(bytes.NewReader(e.Payload[8:16]), binary.LittleEndian, &arg1)
		fields["arg0"] = arg0
		fields["arg1"] = arg1
	}

	return Event{
		ProbeID:   e.ProbeID,
		PID:       e.PID,
		Timestamp: e.TimestampNs,
		Label:     label,
		Fields:    fields,
	}, nil
}

func cString(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i == -1 {
		return string(b)
	}
	return string(b[:i])
}