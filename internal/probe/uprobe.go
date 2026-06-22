package probe

import (
	"debug/elf"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func resolveSymbolOffset(binaryPath, symbol string) (uint64, error) {
	f, err := elf.Open(binaryPath)
	if err != nil {
		return 0, fmt.Errorf("opening binary %s: %w", binaryPath, err)
	}
	defer func() { _ = f.Close() }()

	syms, err := f.Symbols()
	if err != nil {
		syms, err = f.DynamicSymbols()
		if err != nil {
			return 0, fmt.Errorf("reading symbols from %s: %w", binaryPath, err)
		}
	}

	for _, s := range syms {
		if s.Name == symbol {
			return s.Value, nil
		}
	}
	return 0, fmt.Errorf("symbol %q not found in %s (binary may be stripped — try `nm -D %s | grep %s`)",
		symbol, binaryPath, binaryPath, symbol)
}

// ValidateSymbol is a dry-run-safe check — confirms the binary exists and
// the symbol resolves, without requiring root or attaching anything.
func ValidateSymbol(binaryPath, symbol string) error {
	_, err := resolveSymbolOffset(binaryPath, symbol)
	return err
}

type AttachedUprobe struct {
	entry link.Link
	exit  link.Link
}

func (a *AttachedUprobe) Close() error {
	var firstErr error
	if a.exit != nil {
		if err := a.exit.Close(); err != nil {
			firstErr = err
		}
	}
	if a.entry != nil {
		if err := a.entry.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// UprobeAttachment bundles the attached link(s) with the loaded Collection,
// since callers (trace.go) need direct access to coll.Maps["events"] for
// the ring buffer reader.
type UprobeAttachment struct {
	*AttachedUprobe
	Collection *ebpf.Collection
}

// AttachUprobe loads bpf/uprobe.bpf.o and attaches the program(s) matching
// probeType ("uprobe", "uprobe_pair", "uretprobe") to symbol inside binary,
// filtered to pid. probeID is written into the BPF program's read-only
// global so emitted events self-report which probe produced them.
func AttachUprobe(probeType, binary, symbol string, pid uint32, probeID uint32) (*UprobeAttachment, error) {
	if binary == "" {
		return nil, fmt.Errorf("uprobe attach: binary path is required")
	}
	if symbol == "" {
		return nil, fmt.Errorf("uprobe attach: symbol is required")
	}

	spec, err := ebpf.LoadCollectionSpec("bpf/uprobe.bpf.o")
	if err != nil {
		return nil, fmt.Errorf("loading uprobe BPF object: %w", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid":    pid,
		"this_probe_id": probeID,
	}); err != nil {
		return nil, fmt.Errorf("setting constants: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("kernel rejected uprobe BPF program: %w", err)
	}

	ex, err := link.OpenExecutable(binary)
	if err != nil {
		coll.Close()
		return nil, fmt.Errorf("opening executable %s: %w", binary, err)
	}

	switch probeType {
	case "uprobe":
		l, err := ex.Uprobe(symbol, coll.Programs["handle_uprobe_entry"], nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attaching uprobe to %s: %w", symbol, err)
		}
		return &UprobeAttachment{AttachedUprobe: &AttachedUprobe{entry: l}, Collection: coll}, nil

	case "uretprobe":
		l, err := ex.Uretprobe(symbol, coll.Programs["handle_uretprobe_only"], nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attaching uretprobe to %s: %w", symbol, err)
		}
		return &UprobeAttachment{AttachedUprobe: &AttachedUprobe{entry: l}, Collection: coll}, nil

	case "uprobe_pair":
		entry, err := ex.Uprobe(symbol, coll.Programs["handle_uprobe_pair_entry"], nil)
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("attaching uprobe_pair entry to %s: %w", symbol, err)
		}
		exit, err := ex.Uretprobe(symbol, coll.Programs["handle_uprobe_pair_exit"], nil)
		if err != nil {
			_ = entry.Close()
			coll.Close()
			return nil, fmt.Errorf("attaching uprobe_pair exit to %s: %w", symbol, err)
		}
		return &UprobeAttachment{AttachedUprobe: &AttachedUprobe{entry: entry, exit: exit}, Collection: coll}, nil

	default:
		coll.Close()
		return nil, fmt.Errorf("AttachUprobe called with non-uprobe type %q", probeType)
	}
}