package probe

import "fmt"

// ProbeConfig is the top-level structure of a .yaml probe file.
type ProbeConfig struct {
    Name        string        `yaml:"name"`
    Description string        `yaml:"description"`
    Version     string        `yaml:"version"`
    Binary      string        `yaml:"binary,omitempty"`
    Probes      []ProbeEntry  `yaml:"probes"`
    Output      OutputConfig  `yaml:"output"`
}

type ProbeEntry struct {
    Name        string        `yaml:"name"`
    Type        string        `yaml:"type"`        // tracepoint, kprobe, kprobe_pair, uprobe, etc.
    Event       string        `yaml:"event,omitempty"`
    EntryEvent  string        `yaml:"entry_event,omitempty"`
    ExitEvent   string        `yaml:"exit_event,omitempty"`
    Binary      string        `yaml:"binary,omitempty"`
    Symbol      string        `yaml:"symbol,omitempty"`
    Fields      []FieldDef    `yaml:"fields,omitempty"`
    Filter      *FilterDef    `yaml:"filter,omitempty"`
    Latency     *LatencyDef   `yaml:"latency,omitempty"`
    StackTrace  *StackDef     `yaml:"stack_trace,omitempty"`
    Output      *ProbeOutput  `yaml:"output,omitempty"`
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

type StackDef struct {
    Enabled bool `yaml:"enabled"`
    Depth   int  `yaml:"depth"`
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

// ValidProbeTypes is the complete enum of supported probe types.
var ValidProbeTypes = map[string]bool{
    "tracepoint":      true,
    "kprobe":          true,
    "kprobe_pair":     true,
    "uprobe":          true,
    "uprobe_pair":     true,
    "uretprobe":       true,
    "tracepoint_pair": true,
}

// Validate checks the config for required fields and unknown probe types.
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
        if !ValidProbeTypes[p.Type] {
            return fmt.Errorf("probe %q has unknown type %q — valid types: tracepoint, kprobe, kprobe_pair, uprobe, uprobe_pair, uretprobe, tracepoint_pair", p.Name, p.Type)
        }
        if p.Type == "tracepoint" || p.Type == "kprobe" {
            if p.Event == "" {
                return fmt.Errorf("probe %q (type=%s) requires field: event", p.Name, p.Type)
            }
        }
        if p.Type == "kprobe_pair" || p.Type == "tracepoint_pair" {
            if p.EntryEvent == "" || p.ExitEvent == "" {
                return fmt.Errorf("probe %q (type=%s) requires both entry_event and exit_event", p.Name, p.Type)
            }
        }
        if p.Type == "uprobe" || p.Type == "uprobe_pair" || p.Type == "uretprobe" {
            if p.Symbol == "" {
                return fmt.Errorf("probe %q (type=%s) requires field: symbol", p.Name, p.Type)
            }
        }
    }
    return nil
}