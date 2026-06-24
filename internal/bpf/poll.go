package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ── Syscall counts ──────────────────────────────────────────────────────────

type SyscallCount struct {
	Nr    uint32
	Name  string
	Count uint64
}

// PollSyscallCounts attaches syscall_counter.bpf.o to pid and calls onUpdate
// with the ranked, named counts once per interval, until stop is closed.
// nameFn resolves a syscall number to a human name (caller-supplied so this
// package stays free of the arch-specific syscallNames table living in main).
func PollSyscallCounts(pid uint32, interval time.Duration, nameFn func(uint32) string, onUpdate func([]SyscallCount), stop <-chan struct{}) error {
	tracer, err := NewTracer("bpf/syscall_counter.bpf.o", pid)
	if err != nil {
		return fmt.Errorf("failed to start tracer: %w", err)
	}
	defer tracer.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			var counts []SyscallCount
			iter := tracer.CountsMap.Iterate()
			var nr uint32
			var count uint64
			for iter.Next(&nr, &count) {
				counts = append(counts, SyscallCount{Nr: nr, Name: nameFn(nr), Count: count})
			}
			if err := iter.Err(); err != nil {
				continue // transient; next tick will retry
			}
			sort.Slice(counts, func(i, j int) bool { return counts[i].Count > counts[j].Count })
			onUpdate(counts)
		}
	}
}

// ── Latency histogram ───────────────────────────────────────────────────────

const MaxLatencyBuckets = 32

// PollLatencyHistogram attaches latency.bpf.o filtered to pid+syscallNr and
// calls onUpdate with the full 32-bucket histogram once per interval.
func PollLatencyHistogram(pid, syscallNr uint32, interval time.Duration, onUpdate func([MaxLatencyBuckets]uint64), stop <-chan struct{}) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("bpf/latency.bpf.o")
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}
	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid":     pid,
		"target_syscall": syscallNr,
	}); err != nil {
		return fmt.Errorf("setting constants: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("loading BPF collection: %w", err)
	}
	defer coll.Close()

	enterTP, err := link.Tracepoint("raw_syscalls", "sys_enter", coll.Programs["handle_enter"], nil)
	if err != nil {
		return fmt.Errorf("attaching sys_enter: %w", err)
	}
	defer func() { _ = enterTP.Close() }()

	exitTP, err := link.Tracepoint("raw_syscalls", "sys_exit", coll.Programs["handle_exit"], nil)
	if err != nil {
		return fmt.Errorf("attaching sys_exit: %w", err)
	}
	defer func() { _ = exitTP.Close() }()

	histMap := coll.Maps["histogram"]
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return nil
		case <-ticker.C:
			var buckets [MaxLatencyBuckets]uint64
			for i := uint32(0); i < MaxLatencyBuckets; i++ {
				var val uint64
				if err := histMap.Lookup(&i, &val); err == nil {
					buckets[i] = val
				}
			}
			onUpdate(buckets)
		}
	}
}

// ── Kernel events (mem/sched) ───────────────────────────────────────────────

const (
	EventMemMmap     = 1
	EventMemMunmap   = 2
	EventMemBrk      = 3
	EventSchedSwitch = 4
)

// KernelEvent must match struct event in events.bpf.c exactly — same layout
// as the kernelEvent struct in events.go.
type KernelEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	Type      uint8
	Comm      [16]byte
	Pad       [7]uint8
	Addr      uint64
	Size      uint64
	PrevPID   uint32
	NextPID   uint32
	NextComm  [16]byte
}

// PollEvents attaches events.bpf.o filtered by typeFilter ("mem","sched","all")
// and calls onEvent for every parsed event until stop is closed.
func PollEvents(pid uint32, typeFilter string, onEvent func(KernelEvent), stop <-chan struct{}) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec("bpf/events.bpf.o")
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	captureMem := uint8(0)
	captureSched := uint8(0)
	if typeFilter == "mem" || typeFilter == "all" {
		captureMem = 1
	}
	if typeFilter == "sched" || typeFilter == "all" {
		captureSched = 1
	}

	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid":    pid,
		"capture_mem":   captureMem,
		"capture_sched": captureSched,
	}); err != nil {
		return fmt.Errorf("setting constants: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("loading BPF collection: %w", err)
	}
	defer coll.Close()

	if captureMem == 1 {
		memLink, err := link.Tracepoint("raw_syscalls", "sys_enter", coll.Programs["trace_mem_syscalls"], nil)
		if err != nil {
			return fmt.Errorf("attaching raw_syscalls/sys_enter: %w", err)
		}
		defer func() { _ = memLink.Close() }()
	}

	if captureSched == 1 {
		schedLink, err := link.Tracepoint("sched", "sched_switch", coll.Programs["trace_sched_switch"], nil)
		if err != nil {
			return fmt.Errorf("attaching sched/sched_switch: %w", err)
		}
		defer func() { _ = schedLink.Close() }()
	}

	rd, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return fmt.Errorf("opening ring buffer: %w", err)
	}
	defer func() { _ = rd.Close() }()

	go func() {
		<-stop
		_ = rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		var e KernelEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.NativeEndian, &e); err != nil {
			continue
		}

		if typeFilter == "mem" && e.Type == EventSchedSwitch {
			continue
		}
		if typeFilter == "sched" && e.Type != EventSchedSwitch {
			continue
		}

		onEvent(e)
	}
}