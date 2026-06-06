# Contributing to Tracery

## Adding a New Probe Type

1. Write the BPF program in `bpf/yourprobe.bpf.c`
   - Include `vmlinux.h`, `bpf_helpers.h`, `bpf_tracing.h`
   - Use `BPF_CORE_READ` for all kernel struct field access
   - Use `bpf_ringbuf_reserve/submit` for event streaming
   - Use `BPF_MAP_TYPE_HASH` for per-TID state
   - Always filter by `target_pid` if 0 = trace all

2. Add the compile target to `Makefile`

3. Write the Go command in `yourcommand.go`
   - Match the C struct layout exactly in Go
   - Use `binary.NativeEndian` for deserialization
   - Register the command in `main.go`

4. Test on at least two kernel versions

## Code Style

- BPF C: follow Linux kernel style (tabs, 80 col)
- Go: `gofmt` enforced, `golint` clean
- Commit messages: `feat:`, `fix:`, `docs:`, `refactor:`

## Verifier Errors

If the BPF verifier rejects your program:
- Add `BPF_CORE_READ` around every kernel struct access
- Check pointer arithmetic — verifier tracks all pointer bounds
- Reduce program complexity if hitting instruction limit
- Post the full verifier log to the issue tracker