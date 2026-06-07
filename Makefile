CLANG      := clang-16
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_arm64

.PHONY: all build clean bpf

.PHONY: setup
setup:
	sudo bash setup.sh

.PHONY: test lint

test:
	go test ./...

lint:
	golangci-lint run ./...
	
all: bpf build

bpf: bpf/syscall_counter.bpf.o bpf/latency.bpf.o bpf/events.bpf.o bpf/stack.bpf.o

bpf/stack.bpf.o: bpf/stack.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I/usr/include/bpf \
		-c bpf/stack.bpf.c \
		-o bpf/stack.bpf.o

bpf/syscall_counter.bpf.o: bpf/syscall_counter.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I/usr/include/bpf \
		-c bpf/syscall_counter.bpf.c \
		-o bpf/syscall_counter.bpf.o

bpf/latency.bpf.o: bpf/latency.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I/usr/include/bpf \
		-c bpf/latency.bpf.c \
		-o bpf/latency.bpf.o

bpf/events.bpf.o: bpf/events.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) \
		-I./bpf \
		-I/usr/include/bpf \
		-c bpf/events.bpf.c \
		-o bpf/events.bpf.o

build:
	go build -o tracery .

clean:
	rm -f bpf/*.o tracery