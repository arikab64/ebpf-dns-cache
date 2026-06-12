BPFTOOL  ?= bpftool
CARGO    ?= cargo

VMLINUX  := vmlinux.h

# BPF sources and the generated Rust skeleton. The skeleton is checked in and
# included by src/main.rs; it must be regenerated whenever the BPF C or its
# headers change. `-I.` lets clang find vmlinux.h at the repo root.
BPF_SRC    := src/bpf/dns_parser.bpf.c
BPF_HDRS   := src/bpf/dns_parser.h $(VMLINUX)
SKEL       := src/bpf/dns_parser.skel.rs
CLANG_ARGS := -I.

.PHONY: all build release test test-one clean vmlinux skel

all: build

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

vmlinux: $(VMLINUX)

# Regenerate the skeleton only when the BPF C source or its headers are newer
# than the existing skeleton (Make compares timestamps). Compiles
# src/bpf/*.bpf.c -> target/bpf/*.bpf.o, then generates the Rust skeleton.
$(SKEL): $(BPF_SRC) $(BPF_HDRS)
	$(CARGO) libbpf build --clang-args=$(CLANG_ARGS)
	$(CARGO) libbpf gen

skel: $(SKEL)

build: $(SKEL)
	$(CARGO) build

release: $(SKEL)
	$(CARGO) build --release

# BPF programs need root to load, so build the test binary unprivileged
# then run it under sudo.
test: $(SKEL)
	$(CARGO) test --no-run
	sudo "$$($(CARGO) test --no-run --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | grep -v 'null' | cut -d'"' -f4 | head -1)" --test-threads=1

# Run a single test by name, e.g. `make test-one TEST=parses_dns_response`.
# TEST is matched exactly; output is uncaptured so bpf_printk/println! show.
test-one: $(SKEL)
ifndef TEST
	$(error TEST is not set. Usage: make test-one TEST=<test_name>)
endif
	$(CARGO) test --no-run
	sudo "$$($(CARGO) test --no-run --message-format=json 2>/dev/null | grep -o '"executable":"[^"]*"' | grep -v 'null' | cut -d'"' -f4 | head -1)" \
		$(TEST) --exact --test-threads=1 --nocapture

clean:
	$(CARGO) clean
	rm -f $(VMLINUX) $(SKEL)
