// SPDX-License-Identifier: GPL-2.0
//
// syscall_counter.bpf.c
//
// Counts syscalls per syscall number for a target PID.
// Uses a BPF hash map: syscall_nr → count.
// Userspace polls this map every second and prints a table.
//
// This is different from mini 3 and 4 — we don't use a ring
// buffer here because we don't need individual events.
// We just need aggregated counts. A hash map is perfect for that.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// -------------------------------------------------------
// THE COUNTING MAP
//
// Key:   u32 syscall number (e.g. 63 = read on ARM64)
// Value: u64 count (how many times this syscall was called)
//
// Every time our BPF program fires, it increments the
// counter for that syscall number.
// Go reads this entire map every second to print the table.
// -------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);  // 512 possible syscall numbers
    __type(key,   u32);        // syscall number
    __type(value, u64);        // count
} syscall_counts SEC(".maps");

// Target PID — set by userspace before loading
const volatile pid_t target_pid = 0;

SEC("tracepoint/raw_syscalls/sys_enter")
int count_syscalls(struct trace_event_raw_sys_enter *ctx)
{
    // Get PID
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    // Filter to target PID
    if (target_pid != 0 && pid != target_pid)
        return 0;

    // Get syscall number
    u32 syscall_nr = (u32)ctx->id;

    // -------------------------------------------------------
    // Increment the counter for this syscall.
    //
    // We can't just do syscall_counts[nr]++ in BPF.
    // The safe pattern is:
    //   1. Look up current value
    //   2. If exists, increment it
    //   3. If not, initialize to 1
    // -------------------------------------------------------
    u64 *count = bpf_map_lookup_elem(&syscall_counts, &syscall_nr);
    if (count) {
        // Syscall seen before — increment existing counter
        __sync_fetch_and_add(count, 1);
    } else {
        // First time seeing this syscall — initialize to 1
        u64 init = 1;
        bpf_map_update_elem(&syscall_counts, &syscall_nr, &init, BPF_ANY);
    }

    return 0;
}
