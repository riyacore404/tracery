// SPDX-License-Identifier: GPL-2.0
//
// latency.bpf.c
//
// Measures syscall latency using entry/exit probe pairs.
// Stores results in a log2 histogram — each bucket represents
// a power-of-2 range of nanoseconds.
//
// Bucket 0  = 0-1ns
// Bucket 10 = 1024ns  (~1µs)
// Bucket 20 = 1048576ns (~1ms)
// Bucket 30 = 1073741824ns (~1s)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// Number of histogram buckets.
// Each bucket i covers latencies from 2^(i-1) to 2^i nanoseconds.
#define MAX_BUCKETS 32

// -------------------------------------------------------
// MAP 1: entry_times
// Stores the entry timestamp for each thread.
// Key: TID, Value: nanosecond timestamp at syscall entry.
// Same pattern as mini 4.
// -------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key,   u32);  // TID
    __type(value, u64);  // entry timestamp in nanoseconds
} entry_times SEC(".maps");

// -------------------------------------------------------
// MAP 2: histogram
// A fixed-size array of 32 buckets.
// Each bucket is a u64 counter.
// Key: bucket index (0-31), Value: count of events in that bucket.
// -------------------------------------------------------
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_BUCKETS);
    __type(key,   u32);  // bucket index
    __type(value, u64);  // count
} histogram SEC(".maps");

// Filter to specific PID
const volatile pid_t target_pid = 0;

// Which syscall to measure — set by userspace before loading.
// 63 = read on ARM64
const volatile u32 target_syscall = 63;

// -------------------------------------------------------
// log2 helper
// Returns which histogram bucket a duration falls into.
// Works by counting how many times we can right-shift
// until the value reaches zero — that's the log base 2.
// -------------------------------------------------------
static __always_inline u32 log2_bucket(u64 value)
{
    u32 bucket = 0;
    if (value == 0)
        return 0;
    // Each shift right divides by 2 — counts the power of 2
    while (value > 1) {
        value >>= 1;
        bucket++;
    }
    if (bucket >= MAX_BUCKETS)
        bucket = MAX_BUCKETS - 1;
    return bucket;
}

// -------------------------------------------------------
// PROBE 1: sys_enter — record entry timestamp
// -------------------------------------------------------
SEC("tracepoint/raw_syscalls/sys_enter")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    // Only track the target syscall
    if ((u32)ctx->id != target_syscall)
        return 0;

    u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_times, &tid, &ts, BPF_ANY);

    return 0;
}

// -------------------------------------------------------
// PROBE 2: sys_exit — compute latency, update histogram
// -------------------------------------------------------
SEC("tracepoint/raw_syscalls/sys_exit")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;
    u32 tid = (u32)id;

    if (target_pid != 0 && pid != target_pid)
        return 0;

    // Look up entry timestamp
    u64 *entry_ts = bpf_map_lookup_elem(&entry_times, &tid);
    if (!entry_ts)
        return 0;

    // Compute latency
    u64 now      = bpf_ktime_get_ns();
    u64 duration = now - *entry_ts;

    // Clean up entry timestamp
    bpf_map_delete_elem(&entry_times, &tid);

    // Find which bucket this latency belongs to
    u32 bucket = log2_bucket(duration);

    // Increment that bucket's counter
    u64 *count = bpf_map_lookup_elem(&histogram, &bucket);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        u64 init = 1;
        bpf_map_update_elem(&histogram, &bucket, &init, BPF_ANY);
    }

    return 0;
}