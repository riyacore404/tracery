package output

import (
    "encoding/json"
    "fmt"
    "os"
)

// Speedscope file format — https://github.com/speedscope/speedscope/blob/main/src/lib/file-format-spec.ts

type SpeedscopeFile struct {
    Schema   string            `json:"$schema"`
    Shared   SpeedscopeShared  `json:"shared"`
    Profiles []SampledProfile  `json:"profiles"`
    Name     string            `json:"name"`
    ActiveProfileIndex int     `json:"activeProfileIndex"`
    Exporter string            `json:"exporter"`
}

type SpeedscopeShared struct {
    Frames []Frame `json:"frames"`
}

type Frame struct {
    Name string `json:"name"`
    File string `json:"file,omitempty"`
    Line int    `json:"line,omitempty"`
}

type SampledProfile struct {
    Type       string    `json:"type"`
    Name       string    `json:"name"`
    Unit       string    `json:"unit"`
    StartValue float64   `json:"startValue"`
    EndValue   float64   `json:"endValue"`
    Samples    [][]int   `json:"samples"`
    Weights    []float64 `json:"weights"`
}

// StackSample is one collected stack trace with a weight (e.g. latency in ns).
type StackSample struct {
    Frames []string // outermost first
    Weight float64  // nanoseconds
}

// WriteFlamegraph serialises samples into Speedscope JSON and writes to path.
func WriteFlamegraph(path string, profileName string, samples []StackSample) (err error) {
    if len(samples) == 0 {
        return fmt.Errorf("no samples to write")
    }

    // Build a frame index — deduplicate frame names
    frameIndex := map[string]int{}
    var frames []Frame
    for _, s := range samples {
        for _, f := range s.Frames {
            if _, exists := frameIndex[f]; !exists {
                frameIndex[f] = len(frames)
                frames = append(frames, Frame{Name: f})
            }
        }
    }

    // Build samples and weights arrays
    var samplesList [][]int
    var weights []float64
    var endValue float64

    for _, s := range samples {
        var indices []int
        for _, f := range s.Frames {
            indices = append(indices, frameIndex[f])
        }
        samplesList = append(samplesList, indices)
        weights = append(weights, s.Weight)
        endValue += s.Weight
    }

    out := SpeedscopeFile{
        Schema: "https://www.speedscope.app/file-format-schema.json",
        Shared: SpeedscopeShared{Frames: frames},
        Profiles: []SampledProfile{{
            Type:       "sampled",
            Name:       profileName,
            Unit:       "nanoseconds",
            StartValue: 0,
            EndValue:   endValue,
            Samples:    samplesList,
            Weights:    weights,
        }},
        Name:               profileName,
        ActiveProfileIndex: 0,
        Exporter:           "tracery",
    }

    f, err := os.Create(path)
    if err != nil {
        return fmt.Errorf("creating %s: %w", path, err)
    }
    defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("closing %s: %w", path, cerr)
		}
	}()

    enc := json.NewEncoder(f)
    enc.SetIndent("", "  ")
    if err := enc.Encode(out); err != nil {
        return fmt.Errorf("encoding flamegraph JSON: %w", err)
    }
    return nil
}