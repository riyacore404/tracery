package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/riyacore/tracery/internal/output"
)

// ── YAML schema structs ───────────────────────────────────────────────────────

type ProbeConfig struct {
	Name        string        `yaml:"name"`
	Description string        `yaml:"description"`
	Version     string        `yaml:"version"`
	Binary      string        `yaml:"binary,omitempty"`
	Probes      []ProbeEntry  `yaml:"probes"`
	Output      OutputConfig  `yaml:"output"`
}

type ProbeEntry struct {
	Name       string       `yaml:"name"`
	Type       string       `yaml:"type"`
	Event      string       `yaml:"event,omitempty"`
	EntryEvent string       `yaml:"entry_event,omitempty"`
	ExitEvent  string       `yaml:"exit_event,omitempty"`
	Binary     string       `yaml:"binary,omitempty"`
	Symbol     string       `yaml:"symbol,omitempty"`
	Fields     []FieldDef   `yaml:"fields,omitempty"`
	Filter     *FilterDef   `yaml:"filter,omitempty"`
	Latency    *LatencyDef  `yaml:"latency,omitempty"`
	Output     *ProbeOutput `yaml:"output,omitempty"`
}

type FieldDef struct {
	Name   string `yaml:"name"`
	Type   string `yaml:"type"`
	Source string `yaml:"source"`
}

type FilterDef struct {
	Expr string `yaml:"expr"`
}

type LatencyDef struct {
	Enabled   bool          `yaml:"enabled"`
	Unit      string        `yaml:"unit"`
	Histogram *HistogramDef `yaml:"histogram,omitempty"`
}

type HistogramDef struct {
	Type    string `yaml:"type"`
	MinNs   int64  `yaml:"min_ns"`
	MaxNs   int64  `yaml:"max_ns"`
	Buckets int    `yaml:"buckets"`
}

type ProbeOutput struct {
	Label  string `yaml:"label,omitempty"`
	Format string `yaml:"format,omitempty"`
}

type OutputConfig struct {
	Format    string `yaml:"format"`
	Timestamp bool   `yaml:"timestamp"`
	Interval  string `yaml:"interval,omitempty"`
}

var validProbeTypes = map[string]bool{
	"tracepoint":      true,
	"kprobe":          true,
	"kprobe_pair":     true,
	"uprobe":          true,
	"uprobe_pair":     true,
	"uretprobe":       true,
	"tracepoint_pair": true,
}

func (c *ProbeConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("config missing required field: name")
	}
	if len(c.Probes) == 0 {
		return fmt.Errorf("config %q defines no probes", c.Name)
	}
	for i, p := range c.Probes {
		if p.Name == "" {
			return fmt.Errorf("probe[%d] missing required field: name", i)
		}
		if !validProbeTypes[p.Type] {
			return fmt.Errorf("probe %q has unknown type %q", p.Name, p.Type)
		}
		if (p.Type == "tracepoint" || p.Type == "kprobe") && p.Event == "" {
			return fmt.Errorf("probe %q (type=%s) requires field: event", p.Name, p.Type)
		}
		if (p.Type == "kprobe_pair" || p.Type == "tracepoint_pair") && (p.EntryEvent == "" || p.ExitEvent == "") {
			return fmt.Errorf("probe %q (type=%s) requires entry_event and exit_event", p.Name, p.Type)
		}
		if (p.Type == "uprobe" || p.Type == "uprobe_pair" || p.Type == "uretprobe") && p.Symbol == "" {
			return fmt.Errorf("probe %q (type=%s) requires field: symbol", p.Name, p.Type)
		}
	}
	return nil
}

// ── Command ───────────────────────────────────────────────────────────────────

var (
	traceConfigPath string
	traceDryRun     bool
	traceOutputFmt  string
	tracePIDFlag    int
)

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Run probes defined in a YAML config file",
	Example: `  sudo tracery trace --config examples/latency-analysis.yaml --pid 1234
  sudo tracery trace --config examples/syscall-audit.yaml --pid 1234 --output json
  sudo tracery trace --config examples/latency-analysis.yaml --pid 1234 --dry-run`,
	RunE: runTrace,
}

func init() {
	traceCmd.Flags().StringVar(&traceConfigPath, "config", "", "Path to YAML probe config file (required)")
	traceCmd.Flags().IntVar(&tracePIDFlag, "pid", 0, "Target process PID (required)")
	traceCmd.Flags().BoolVar(&traceDryRun, "dry-run", false, "Parse and validate config without attaching probes")
	traceCmd.Flags().StringVar(&traceOutputFmt, "output", "table", "Output format: table, json")
	
	if err := traceCmd.MarkFlagRequired("config"); err != nil {
		panic(err)
	}
	if err := traceCmd.MarkFlagRequired("pid"); err != nil {
		panic(err)
	}

	rootCmd.AddCommand(traceCmd)
}

func runTrace(cmd *cobra.Command, args []string) error {
	data, err := os.ReadFile(traceConfigPath)
	if err != nil {
		return fmt.Errorf("reading config %s: %w", traceConfigPath, err)
	}

	var cfg ProbeConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	if traceDryRun {
		fmt.Printf("Config:  %s\n", traceConfigPath)
		fmt.Printf("Name:    %s\n", cfg.Name)
		fmt.Printf("PID:     %d\n", tracePIDFlag)
		fmt.Printf("Probes (%d):\n", len(cfg.Probes))
		for i, p := range cfg.Probes {
			event := p.Event
			if event == "" {
				event = p.EntryEvent + " → " + p.ExitEvent
			}
			fmt.Printf("  [%d] %-24s type=%-16s event=%s\n", i+1, p.Name, p.Type, event)
		}
		fmt.Println("\n✓ Config is valid — dry run complete, no probes attached.")
		return nil
	}

	// ── Live trace ────────────────────────────────────────────────────────────

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	// Load the stack BPF object
	spec, err := ebpf.LoadCollectionSpec("bpf/stack.bpf.o")
	if err != nil {
		return fmt.Errorf("loading stack BPF object: %w", err)
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid": uint32(tracePIDFlag),
	}); err != nil {
		return fmt.Errorf("setting target_pid: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("kernel rejected BPF program: %w", err)
	}
	defer coll.Close()

	tp, err := link.Tracepoint("raw_syscalls", "sys_enter",
		coll.Programs["capture_stack"], nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	defer func() {
		if err := tp.Close(); err != nil {
			log.Warn().Err(err).Msg("error closing tracepoint")
		}
	}()

	log.Info().
		Int("pid", tracePIDFlag).
		Str("config", traceConfigPath).
		Msg("stack tracer attached")

	// Read /proc/PID/maps for symbol resolution
	regions, err := output.ReadMaps(uint32(tracePIDFlag))
	if err != nil {
		log.Warn().Err(err).Msg("could not read process maps — addresses will show as hex")
	}

	// Open ring buffer
	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("opening ring buffer: %w", err)
	}
	defer func() {
		if err := rd.Close(); err != nil {
			log.Warn().Err(err).Msg("error closing ring buffer")
		}
	}()

	// Collect samples for flame graph
	var samples []output.StackSample
	stackMap := coll.Maps["stack_traces"]

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sig
		log.Info().Msg("shutting down — writing flame graph")
		if err := rd.Close(); err != nil {
			log.Warn().Err(err).Msg("error closing ring buffer on signal")
		}
	}()

	fmt.Printf("Tracing PID %d — Ctrl+C to stop and write flame graph\n", tracePIDFlag)

	// ── Stack event struct — must match stack.bpf.c exactly ──────────────────
	type stackEvent struct {
		TimestampNs uint64
		PID         uint32
		TID         uint32
		StackID     int32
		Comm        [16]byte
	}

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Error().Err(err).Msg("ring buffer read error")
			continue
		}

		var e stackEvent
		if err := binary.Read(
			bytes.NewReader(record.RawSample),
			binary.NativeEndian,
			&e,
		); err != nil {
			log.Debug().Err(err).Msg("failed to parse stack event")
			continue
		}

		if e.StackID < 0 {
			continue // bpf_get_stackid failed — skip
		}

		// Look up the stack trace addresses from the stack map
		var addrs [127]uint64
		if err := stackMap.Lookup(uint32(e.StackID), &addrs); err != nil {
			continue
		}

		frames := output.ResolveStack(addrs[:], regions)
		if len(frames) == 0 {
			continue
		}

		samples = append(samples, output.StackSample{
			Frames: frames,
			Weight: 1, // each syscall counts as weight 1
		})
	}

	// Write flame graph output
	outPath := "flamegraph.json"
	if traceOutputFmt == "json" {
		outPath = "flamegraph.json"
	}

	if len(samples) == 0 {
		fmt.Println("No stack samples collected.")
		return nil
	}

	if err := output.WriteFlamegraph(outPath, cfg.Name, samples); err != nil {
		return fmt.Errorf("writing flame graph: %w", err)
	}

	fmt.Printf("✓ Flame graph written to %s — open at speedscope.app\n", outPath)
	fmt.Printf("  %d stack samples collected\n", len(samples))
	return nil
}