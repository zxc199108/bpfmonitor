# Makefile - Build libbpf-based BPF system monitor
# For RK3588 ARM64, Ubuntu 24.04, Linux 6.1

CLANG   ?= clang
CFLAGS  := -g -O2 -target bpf -D__TARGET_ARCH_arm64
LIBBPF  := -lbpf -lelf -lz
INCLUDES := -I/usr/include/aarch64-linux-gnu

BPF_SRC  := bpf/monitor.bpf.c
BPF_OBJ  := bpf/monitor.bpf.o
LOADER   := loader

.PHONY: all clean

all: $(BPF_OBJ) $(LOADER)

$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(LOADER): bpf/loader.c
	$(CC) -O2 -Wall -o $@ $< $(LIBBPF) $(INCLUDES)

load: all
	sudo ./$(LOADER)

clean:
	rm -f $(BPF_OBJ) $(LOADER)

help:
	@echo "Targets:"
	@echo "  all      Build BPF object and userspace loader"
	@echo "  load     Build and run with sudo"
	@echo "  clean    Remove build artifacts"
