package aggregator

// Event is the normalized, decoded form of any probe event, regardless of
// which BPF program produced it. Renderers (table/json/flamegraph) consume
// this type, not the raw EventT wire struct.
type Event struct {
	ProbeID   uint32
	PID       uint32
	Timestamp uint64
	Label     string
	Fields    map[string]any
}

// Probe IDs — must match the #define values in bpf/events.h exactly.
// If these drift out of sync with the C side, events will be mislabeled.
const (
	PROBE_ID_SYSCALL_COUNT = 1
	PROBE_ID_LATENCY_READ  = 2
	PROBE_ID_MEMORY_MMAP   = 3
	PROBE_ID_UPROBE_ENTRY  = 10
	PROBE_ID_UPROBE_PAIR   = 11
	PROBE_ID_URETPROBE     = 12
)