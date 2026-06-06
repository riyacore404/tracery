CLANG      := clang-21
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_arm64

.PHONY: all build clean

all: bpf build

bpf: bpf/syscall_counter.bpf.o

bpf/syscall_counter.bpf.o: bpf/syscall_counter.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I/usr/include/bpf \
		-c bpf/syscall_counter.bpf.c \
		-o bpf/syscall_counter.bpf.o

build:
	go build -o tracery .

clean:
	rm -f bpf/syscall_counter.bpf.o tracery
