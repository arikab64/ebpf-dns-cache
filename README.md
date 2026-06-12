# ebpf-dns-cache

An in-kernel DNS response parser built with eBPF XDP and Rust. It captures DNS A/AAAA records from live network traffic at the network driver level, before packets reach the kernel networking stack.

## Concept

Every DNS response carries a mapping from a domain name to one or more IP addresses. Normally, user-space resolvers (glibc, systemd-resolved) handle this — but they are invisible to programs that want to observe or cache these mappings at the OS level.

This project attaches an XDP program to a network interface and parses every incoming DNS response in the kernel, emitting structured events (domain → IP) to user space via a ring buffer. The goal is zero-copy, low-overhead DNS observation that works independently of the resolver in use.

## Architecture

```
NIC → XDP hook → [xdp_dns_ingress]
                      │
                      ├─ Non-DNS?  → XDP_PASS (unchanged)
                      │
                      └─ DNS response:
                           │
                           ├─ Raw payload → dns_capture_rb (debug)
                           │
                           └─ tail-call chain:
                                ┌──────────────────────┐
                                │  xdp_dns_parse_fqdn  │◄─┐
                                │  (label parser)      │  │ recursion via
                                └──────────┬───────────┘  │ tail-call
                                           │              │
                              ┌────────────┴─────────┐    │
                              ▼                       ▼    │
                     xdp_dns_walk_question   xdp_dns_walk_answer
                     (skip questions)        (emit A/AAAA events)
                                                      │
                                                      ▼
                                               events ringbuf
                                                      │
                                               Rust user space
                                               (print / store)
```

### Why XDP?

XDP (eXpress Data Path) runs eBPF programs at the earliest point in the receive path — inside the network driver, before `sk_buff` allocation. This means:

- **No copy**: the program reads directly from the DMA buffer.
- **No context switch**: everything happens in the kernel.
- **No interference**: the program passes every packet up unchanged (`XDP_PASS`); it only observes.

### Why tail-calls?

The eBPF verifier limits a single program to a bounded number of instructions. Parsing a DNS response requires walking a variable number of questions and answers, each with a variable-length name — too complex for one program. Tail-calls solve this: each logical stage is a separate eBPF program that jumps into the next via a `BPF_MAP_TYPE_PROG_ARRAY` table, sharing state through a per-CPU map. The chain is:

```
ingress → parse_fqdn → walk_question ──► walk_answer
                ▲            │                │
                └────────────┘   (loop)       │ (loop)
```

`parse_fqdn` can be re-entered from either walker, allowing names in both the question section (for context) and the answer section to be parsed with the same code.

### Per-CPU state

All mutable parser state lives in a `BPF_MAP_TYPE_PERCPU_ARRAY` with one slot. Because XDP processes each packet on the CPU that receives it, no locking is needed — each CPU has its own copy of the state structure.

```c
struct dns_parser_state {
    u16  id;              // DNS transaction ID
    u32  dns_base;        // byte offset of DNS header in packet
    u32  packet_offset;   // current read position
    u16  q_remaining;     // questions left to skip
    u16  a_remaining;     // answers left to parse
    u16  answer_idx;      // index of current answer record
    u8   return_prog;     // which program parse_fqdn should tail-call back to
    char name_buf[512];   // assembled domain name
    cache_entry_t cache[256];     // suffix cache (offset → name window)
    pending_label_t pending[256]; // labels recorded during current name walk
    frame_t stack[16];            // call stack for pointer chains
};
```

## DNS Name Parsing

DNS names are encoded as a sequence of length-prefixed labels followed by a zero byte:

```
03 77 77 77              →  "www"
07 65 78 61 6d 70 6c 65  →  "example"
03 63 6f 6d              →  "com"
00                       →  (end)
```

RFC 1035 also defines **compression pointers**: a two-byte sequence with the top two bits set (`0xC0`) encodes a 14-bit offset into the DNS message where a previously-seen name suffix begins. Real responses use this heavily — a response with four answers to `api.example.com` will encode the name once and point to it three more times.

### Suffix cache

Naively following every pointer by re-parsing from the target offset would be O(n²) in the number of pointer indirections. Instead, the parser builds a suffix cache as it walks each name:

- After parsing `www.example.com`, the cache holds three entries:
  - offset 12 → `"www.example.com"` (15 chars at name_buf[0])
  - offset 16 → `"example.com"` (11 chars at name_buf[4])
  - offset 24 → `"com"` (3 chars at name_buf[12])
- When a subsequent name contains a pointer to offset 16, the parser looks up the cache, finds `"example.com"`, and copies it directly — no re-parsing.

This makes pointer resolution O(1) after the first parse.

### Verifier workarounds

The eBPF verifier tracks the range of every scalar value and rejects programs that perform arithmetic it cannot prove is bounded. The DNS parser is inherently variable-length, which creates friction. Two patterns appear throughout the C code:

```c
// Hide a value's provenance so the verifier treats it as an unknown scalar,
// forcing subsequent masks to be the sole proof of boundedness.
#define BARRIER(var) asm volatile("" : "+r"(var))

// After BARRIER, mask to prove the value fits in a buffer index.
cursor = (cursor + label_len) & (DNS_NAME_BUF - 1);
```

Loop bodies are unrolled with `#pragma clang loop unroll(full)` where the iteration count is known at compile time.


## Build

Requirements: `clang`, `llvm`, `bpftool`, Rust 1.70+, kernel 5.8+.

```bash
# Generate vmlinux.h from the running kernel's BTF
make vmlinux

# Compile the BPF C code and generate the Rust skeleton
make skel

# Build the Rust loader (debug)
make build

# Build optimized
make release

# Run unit tests (requires CAP_BPF / sudo)
make test

# Run a single test by name
make test-one TEST=parses_multi_label_fqdn
```

## Usage

```bash
sudo ./target/debug/ebpf-dns-cache <interface>
# e.g.
sudo ./target/debug/ebpf-dns-cache eth0
```

Example output:

```
INFO [loader] attached xdp_dns_ingress to eth0 (ifindex=2). Ctrl-C to detach.
INFO [loader] [txid=9174 answer=0] api.example.com A 93.184.216.34
INFO [loader] [txid=9174 answer=1] api.example.com A 93.184.216.35
INFO [loader] [txid=2976 answer=0] connectivity-check.ubuntu.com AAAA 2620:2d:4000:1::17
```

Structured logs go to `dns-cache_YYYY-MM-DD_HH-MM-SS.log`. Raw DNS payloads (for debugging or test generation) are written to `payloads.json`.

## Kernel requirements

| Feature | Minimum kernel |
|---------|---------------|
| XDP | 4.8 |
| `BPF_MAP_TYPE_PERCPU_ARRAY` | 4.6 |
| `BPF_MAP_TYPE_PROG_ARRAY` (tail-calls) | 4.2 |
| `BPF_MAP_TYPE_RINGBUF` | 5.8 |
| BTF (for `vmlinux.h`) | 5.2 |

Linux 5.8 or later is recommended.
