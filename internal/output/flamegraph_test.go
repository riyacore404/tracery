package output

import (
    "encoding/json"
    "os"
    "testing"
)

func TestWriteFlamegraph_CreatesFile(t *testing.T) {
    samples := []StackSample{
        {Frames: []string{"main", "http.ListenAndServe", "handle_request"}, Weight: 1500000},
        {Frames: []string{"main", "http.ListenAndServe", "db_query"}, Weight: 3000000},
    }

    path := t.TempDir() + "/test.json"
    if err := WriteFlamegraph(path, "test-profile", samples); err != nil {
        t.Fatalf("WriteFlamegraph failed: %v", err)
    }

    data, err := os.ReadFile(path)
    if err != nil {
        t.Fatalf("output file not created: %v", err)
    }

    var out SpeedscopeFile
    if err := json.Unmarshal(data, &out); err != nil {
        t.Fatalf("output is not valid JSON: %v", err)
    }

    if out.Schema != "https://www.speedscope.app/file-format-schema.json" {
        t.Errorf("wrong schema: %s", out.Schema)
    }
    if len(out.Profiles) != 1 {
        t.Errorf("expected 1 profile, got %d", len(out.Profiles))
    }
    if len(out.Profiles[0].Samples) != 2 {
        t.Errorf("expected 2 samples, got %d", len(out.Profiles[0].Samples))
    }
    // Frames should be deduplicated — "main" and "http.ListenAndServe" appear in both
    if len(out.Shared.Frames) != 4 { // main, ListenAndServe, handle_request, db_query
        t.Errorf("expected 4 unique frames, got %d", len(out.Shared.Frames))
    }
}

func TestWriteFlamegraph_EmptySamples(t *testing.T) {
    err := WriteFlamegraph("/tmp/should-not-exist.json", "empty", []StackSample{})
    if err == nil {
        t.Error("expected error for empty samples, got nil")
    }
}