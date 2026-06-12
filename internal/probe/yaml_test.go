package probe

import "testing"

// ── Validate: happy path ──────────────────────────────────────────────────────

func TestValidate_ValidTracepoint(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "my-probe", Type: "tracepoint", Event: "raw_syscalls/sys_enter"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}
}

func TestValidate_ValidKprobePair(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{
				Name:       "latency-probe",
				Type:       "kprobe_pair",
				EntryEvent: "vfs_read",
				ExitEvent:  "vfs_read_return",
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}
}

func TestValidate_ValidUprobe(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "fn-probe", Type: "uprobe", Symbol: "main.handleRequest", Binary: "/usr/bin/myapp"},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Errorf("expected valid config, got error: %v", err)
	}
}

// ── Validate: error paths ─────────────────────────────────────────────────────

func TestValidate_MissingName(t *testing.T) {
	cfg := ProbeConfig{
		Probes: []ProbeEntry{
			{Name: "p", Type: "tracepoint", Event: "e"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for missing config name, got nil")
	}
}

func TestValidate_NoProbes(t *testing.T) {
	cfg := ProbeConfig{Name: "test", Probes: []ProbeEntry{}}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for empty probes list, got nil")
	}
}

func TestValidate_MissingProbeName(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Type: "tracepoint", Event: "e"}, // Name is empty
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for probe missing name, got nil")
	}
}

func TestValidate_UnknownProbeType(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "p", Type: "magic-probe", Event: "e"},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for unknown probe type, got nil")
	}
}

func TestValidate_TracepointMissingEvent(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "p", Type: "tracepoint"}, // Event is empty
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for tracepoint missing event, got nil")
	}
}

func TestValidate_KprobePairMissingExitEvent(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "p", Type: "kprobe_pair", EntryEvent: "vfs_read"}, // ExitEvent missing
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for kprobe_pair missing exit_event, got nil")
	}
}

func TestValidate_UprobeMissingSymbol(t *testing.T) {
	cfg := ProbeConfig{
		Name: "test",
		Probes: []ProbeEntry{
			{Name: "p", Type: "uprobe"}, // Symbol missing
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for uprobe missing symbol, got nil")
	}
}

func TestValidate_AllProbeTypes(t *testing.T) {
	// Ensure all valid probe types pass validation
	types := []struct {
		ptype      string
		event      string
		entryEvent string
		exitEvent  string
		symbol     string
	}{
		{"tracepoint", "raw_syscalls/sys_enter", "", "", ""},
		{"kprobe", "vfs_read", "", "", ""},
		{"kprobe_pair", "", "vfs_read", "vfs_read_ret", ""},
		{"uprobe", "", "", "", "main.fn"},
		{"uprobe_pair", "", "", "", "main.fn"},
		{"uretprobe", "", "", "", "main.fn"},
		{"tracepoint_pair", "", "sched:sched_wakeup", "sched:sched_switch", ""},
	}

	for _, tc := range types {
		cfg := ProbeConfig{
			Name: "test",
			Probes: []ProbeEntry{{
				Name:       "p",
				Type:       tc.ptype,
				Event:      tc.event,
				EntryEvent: tc.entryEvent,
				ExitEvent:  tc.exitEvent,
				Symbol:     tc.symbol,
			}},
		}
		if err := cfg.Validate(); err != nil {
			t.Errorf("probe type %q failed validation: %v", tc.ptype, err)
		}
	}
}