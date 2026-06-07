# Contributing to Tracery

Thank you for your interest in contributing. This document explains how to add new probe types, fix bugs, improve documentation, and get your changes merged.

---

## Table of Contents

1. [Before You Start](#before-you-start)
2. [Development Setup](#development-setup)
3. [Project Structure](#project-structure)
4. [How to Add a New Probe Type](#how-to-add-a-new-probe-type)
5. [Testing](#testing)
6. [Code Style](#code-style)
7. [Submitting a Pull Request](#submitting-a-pull-request)
8. [Good First Issues](#good-first-issues)
9. [Reporting Bugs](#reporting-bugs)

---

## Before You Start

- Read [ARCHITECTURE.md](ARCHITECTURE.md). Contributions that contradict architectural decisions there will be asked to change. If you disagree with a decision, open an issue to discuss it first.
- Search existing issues before opening a new one. Your bug may already be tracked, or your feature may already be discussed.
- For large changes (new commands, new output formats, significant refactors), open an issue first and describe what you want to do. This saves both of us time.

---

## Development Setup

**Requirements:**
- Ubuntu 22.04 or 24.04 (or compatible Debian). macOS and Windows are not supported — eBPF is Linux-only.
- Kernel 5.8 or later (check: `uname -r`).
- BTF available (check: `ls /sys/kernel/btf/vmlinux`).
- Root or `CAP_BPF` capability.

**One-command setup:**

```bash
sudo bash setup.sh
```

**Manual setup:**

```bash
sudo apt-get install -y clang-16 llvm-16 libelf-dev libbpf-dev bpftool \
    linux-headers-$(uname -r) build-essential pkg-config

# Go 1.22+
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

**Build:**

```bash
make build          # compile BPF objects + Go binary
make test           # run all tests
make lint           # golangci-lint
make clean          # remove build artifacts
```

**First run:**

```bash
sudo ./tracery count --pid $(pgrep bash)
```

---

## Project Structure

```
tracery/
├── bpf/                        # BPF C programs (kernel side)
│   ├── syscall_counter.bpf.c   # M1: syscall count map
│   ├── latency.bpf.c           # M2: read/write latency histogram
│   ├── memory.bpf.c            # M3: mmap/brk/page fault events
│   ├── stack.bpf.c             # M4: stack trace capture
│   ├── events.h                # Shared event_t struct (BPF C + Go)
│   └── vmlinux.h               # Generated: bpftool btf dump ... format c
│
├── cmd/                        # cobra subcommands (one file per command)
│   ├── root.go
│   ├── count.go
│   ├── latency.go
│   ├── trace.go
│   └── bench.go
│
├── internal/
│   ├── bpf/                    # BPF loading and map wrappers
│   ├── aggregator/             # In-memory event aggregation
│   ├── output/                 # Rendering: table, JSON, flame graph
│   └── probe/                  # YAML probe format parser + registry
│
├── examples/                   # Example YAML probe files
├── Makefile
├── .goreleaser.yaml
├── .github/workflows/ci.yaml
├── ARCHITECTURE.md
└── CONTRIBUTING.md             ← you are here
```

---

## How to Add a New Probe Type

This is the most common contribution. Follow these steps in order.

### Step 1: Write the BPF C program

Create `bpf/your_probe.bpf.c`. Use an existing probe as a template:

```c
// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tracery Authors

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "events.h"

// Target PID — set by userspace at attach time
volatile const __u32 target_pid = 0;

// Ring buffer — all events go here
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024); // 4MB default
} events SEC(".maps");

// Drop counter — userspace reads this to surface overflow
volatile __u64 drop_count = 0;

SEC("tracepoint/syscalls/sys_enter_YOUR_SYSCALL")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (target_pid && pid != target_pid)
        return 0;

    struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&drop_count, 1);
        return 0;
    }

    e->pid           = pid;
    e->tid           = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns  = bpf_ktime_get_ns();
    e->probe_id      = PROBE_ID_YOUR_PROBE;  // add to events.h
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Capture probe-specific fields into payload
    // ALWAYS use BPF_CORE_READ — never dereference pointers directly
    // e.g.: e->payload_u64[0] = BPF_CORE_READ(ctx, args[0]);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
```

**Rules for BPF C code:**

- Always use `BPF_CORE_READ()` to access kernel struct fields — never dereference directly.
- Always check the return value of `bpf_ringbuf_reserve()` before using the pointer.
- Always filter by `target_pid` early to avoid tracing the entire system.
- Keep the program under ~100 instructions if possible — the verifier is faster on simple programs.
- Add `__sync_fetch_and_add(&drop_count, 1)` on every early-return path that drops an event.

### Step 2: Regenerate the BPF skeleton

```bash
make bpf-gen    # runs: bpftool gen skeleton bpf/your_probe.bpf.o > bpf/your_probe.skel.h
```

Commit the generated `.skel.h` file. It must be regenerated whenever the BPF C source changes.

### Step 3: Add the probe ID to `events.h`

```c
// bpf/events.h
#define PROBE_ID_SYSCALL_COUNT    1
#define PROBE_ID_LATENCY_READ     2
#define PROBE_ID_MEMORY_MMAP      3
// add yours:
#define PROBE_ID_YOUR_PROBE       N
```

### Step 4: Register the probe type in Go

Add an entry to `internal/probe/registry.go`:

```go
// internal/probe/registry.go
probeRegistry["your-type"] = ProbeHandler{
    Attach: func(cfg ProbeConfig, pid uint32) (*AttachedProbe, error) {
        // Load your BPF skeleton
        // Set target_pid global variable
        // Attach the program to its hook point
        // Return an AttachedProbe that detaches on Close()
    },
    EventParser: parseYourProbeEvent,
}
```

### Step 5: Write the event parser

```go
// internal/aggregator/your_probe.go
func parseYourProbeEvent(raw []byte) (Event, error) {
    var e EventT
    if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
        return Event{}, fmt.Errorf("parsing your_probe event: %w", err)
    }
    return Event{
        ProbeID:   e.ProbeID,
        PID:       e.PID,
        Timestamp: e.TimestampNs,
        Label:     "YOUR_PROBE",
        Fields: map[string]any{
            "field1": e.PayloadU64[0],
            "field2": e.PayloadU64[1],
        },
    }, nil
}
```

### Step 6: Add a YAML probe type entry

Update `internal/probe/yaml.go` to recognise your probe type in the YAML schema. Add it to the `ProbeType` enum and the `validateProbe()` switch.

### Step 7: Write tests

```bash
# Unit test for the Go event parser (no kernel required)
internal/aggregator/your_probe_test.go

# Integration test (requires a kernel with BPF support)
tests/integration/your_probe_test.go
```

See the existing tests in `internal/aggregator/counter_test.go` for the pattern.

### Step 8: Add an example YAML file

Add `examples/your-probe.yaml` with a realistic use case, comments explaining each field, and a usage example in the header.

### Step 9: Update the README

Add your probe type to the "Supported Probe Types" table in `README.md`.

---

## Testing

### Unit tests (no kernel required)

```bash
make test
# or:
go test ./...
```

Unit tests cover: Go aggregation logic, YAML parsing, JSON/histogram rendering, event struct parsing. They do not require a running kernel or root access.

### Integration tests (kernel required, run as root)

```bash
sudo make test-integration
```

Integration tests attach real BPF programs to the kernel and verify events are received. They require kernel 5.8+, BTF, and root.

The CI runs integration tests in QEMU with kernel 5.15 and 6.1. If your change breaks either kernel, the CI will catch it.

### BPF unit tests

For BPF C logic, use `BPF_PROG_TEST_RUN` to test programs without attaching them:

```bash
make test-bpf    # runs bpf/tests/*.bpf.c via BPF_PROG_TEST_RUN
```

---

## Code Style

### Go

- Standard `gofmt` formatting. Run `make fmt` before committing.
- Error wrapping: `fmt.Errorf("loading BPF: %w", err)` — always wrap with context.
- No `log.Fatal` outside of `main.go`. Return errors upward.
- Exported functions must have doc comments.
- No global mutable state outside of the aggregator (which is protected by a mutex).

### BPF C

- Every `bpf_ringbuf_reserve()` must be followed by a null check.
- Every kernel struct access must use `BPF_CORE_READ()`.
- Use `SEC("tracepoint/...")` over `SEC("kprobe/...")` when a stable tracepoint exists.
- Comment non-obvious BPF verifier workarounds with `// verifier: ...`.

### YAML examples

- Every example file must have a block comment at the top with: description, use case, usage examples, and "expected output" description.
- Every field must have an inline comment explaining what it captures.

---

## Submitting a Pull Request

1. Fork the repo and create a branch: `git checkout -b feat/your-probe-type`.
2. Make your changes. Write tests. Run `make test` and `make lint` — both must pass.
3. If you changed BPF C: regenerate skeletons (`make bpf-gen`) and commit them.
4. Write a clear PR description:
   - **What** this change does
   - **Why** it's needed
   - **How** you tested it (kernel version, workload used)
   - Any **known limitations** or follow-up work
5. Keep PRs focused. One feature or fix per PR.
6. PRs that break existing tests will not be merged.

### PR checklist

- [ ] `make test` passes
- [ ] `make lint` passes
- [ ] BPF skeletons regenerated if BPF C changed
- [ ] New probe type has an example YAML file
- [ ] README updated if user-visible behavior changed
- [ ] Commit messages are clear and present-tense ("Add uprobe latency histogram", not "Added...")

---

## Good First Issues

These are issues specifically tagged for new contributors:

- **`good first issue`**: Small, well-scoped, documented. No deep eBPF knowledge required.
- **`docs`**: Documentation improvements — architecture clarifications, example YAML comments, README sections.
- **`test coverage`**: Adding unit tests for existing Go functions that lack them.

To find them: [github.com/riyacore404/tracery/issues?q=label:"good+first+issue"](https://github.com/riyacore404/tracery/issues)

If you're new to eBPF and want guidance on getting started, comment on any `good first issue` and we'll help you get oriented.

---

## Reporting Bugs

Open a GitHub issue with:

1. **Tracery version**: `tracery --version`
2. **Kernel version**: `uname -r`
3. **OS and distro**: `cat /etc/os-release`
4. **BTF available**: `ls /sys/kernel/btf/vmlinux` (yes/no)
5. **Exact command run**: `tracery trace --config examples/latency-analysis.yaml --pid 1234`
6. **Full error output** (include any verifier errors from `dmesg` if the program failed to load)

### BPF verifier errors

If Tracery fails to load a BPF program, run:

```bash
sudo dmesg | grep -E "BPF|bpf|verifier" | tail -30
```

Include the full output in your bug report. Verifier messages include the instruction offset and register state — they are cryptic but diagnostic.

### No events appearing

Check:

```bash
# BPF debug output (if bpf_printk() calls exist in the probe)
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

This rules out whether the BPF program is running at all vs. whether events are being dropped in the ring buffer.

---

*Questions? Open an issue or email the maintainers listed in the README.*