# Tracery Makefile
# Supports: Ubuntu 22.04/24.04, ARM64 (aarch64) and x86_64

# ── Architecture detection ────────────────────────────────────────────────────
ARCH := $(shell uname -m)
ifeq ($(ARCH),aarch64)
    BPF_ARCH := arm64
else ifeq ($(ARCH),x86_64)
    BPF_ARCH := x86
else
    BPF_ARCH := $(ARCH)
endif

# ── Clang detection ───────────────────────────────────────────────────────────
# Try clang in order: clang-16, clang-14, clang (system default)
ifneq ($(shell which clang-16 2>/dev/null),)
    CLANG := clang-16
else ifneq ($(shell which clang-14 2>/dev/null),)
    CLANG := clang-14
else
    CLANG := clang
endif

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
              -I./bpf \
              -I/usr/include/bpf

BPF_SRCS := $(wildcard bpf/*.bpf.c)
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

GO      := go
BINARY  := tracery

.PHONY: all bpf build test lint clean fmt

all: bpf build

# ── BPF compilation ───────────────────────────────────────────────────────────
bpf: $(BPF_OBJS)

bpf/%.bpf.o: bpf/%.bpf.c bpf/events.h bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# ── Go binary ─────────────────────────────────────────────────────────────────
build: bpf
	$(GO) build -o $(BINARY) .

# ── Tests ─────────────────────────────────────────────────────────────────────
test:
	$(GO) test ./...

test-verbose:
	$(GO) test -v ./...

# ── Lint ──────────────────────────────────────────────────────────────────────
lint: test
	golangci-lint run --no-config --enable=errcheck,govet,staticcheck ./...

# ── Format ───────────────────────────────────────────────────────────────────
fmt:
	$(GO) fmt ./...

# ── Clean ─────────────────────────────────────────────────────────────────────
clean:
	rm -f bpf/*.o $(BINARY)

# ── vmlinux.h generation ──────────────────────────────────────────────────────
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# ── Info ──────────────────────────────────────────────────────────────────────
info:
	@echo "Arch:   $(ARCH) → BPF_ARCH=$(BPF_ARCH)"
	@echo "Clang:  $(CLANG)"
	@echo "BPF sources: $(BPF_SRCS)"