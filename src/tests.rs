//! Unit tests for the XDP DNS parser, driven through BPF_PROG_TEST_RUN.
//!
//! These tests load the real BPF object, populate the tail-call `jmp_table`
//! exactly like the main binary does, feed crafted packets into `xdp_dns_ingress`
//! via `Program::test_run`, and assert on the resulting parser state.
//!
//! Loading and running BPF programs requires privileges (CAP_BPF /
//! CAP_SYS_ADMIN), so this suite must be run as root, e.g.:
//!
//!     cargo test --no-run
//!     sudo target/debug/deps/ebpf_dns_cache-<hash> --test-threads=1

use std::cell::RefCell;
use std::collections::VecDeque;
use std::mem::{align_of, size_of};
use std::os::fd::{AsFd, AsRawFd};
use std::rc::Rc;

use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, MapFlags, RingBuffer, RingBufferBuilder};

use crate::dns_parser::*;

// keep in sync with PROG_PARSE_FQDN in src/bpf/dns_parser.h
const PROG_PARSE_FQDN: u32 = 0;
const PROG_WALK_QUESTION: u32 = 1;
const PROG_WALK_ANSWER: u32 = 2;
const PROG_EMIT_EVENTS: u32 = 3;

// XDP action codes (uapi/linux/bpf.h)
const XDP_PASS: u32 = 2;

// Mirror of `dns_parser_state_t` from src/bpf/dns_parser.h. The C struct is
// not packed, so the natural C/`repr(C)` layout must match field-for-field.
const DNS_NAME_BUF: usize = 512;
const DNS_MAX_ENTRIES: usize = 256;
const DNS_MAX_DEPTH: usize = 16;

/// Mirror of `pending_label_t` (a label start recorded during the walk).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PendingLabel {
    key_offset:   u16,
    start_cursor: u16,
}

/// Mirror of `cache_entry_t` (one suffix produced by `finalize`).
///
/// `offset` is the DNS-header-relative offset of the label's length byte,
/// `start`/`len` window the suffix text inside `name_buf`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CacheEntry {
    offset: u16,
    start:  u16,
    len:    u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Frame {
    return_prog:  u16,
    start_cursor: u16,
    key_offset:   u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DnsParserState {
    id:            u16,
    qcount:        u16,
    acount:        u16,
    cpu:           u32,
    dns_base:      u32,
    packet_offset: u32,
    cursor:        u64,
    name_start:    u32,
    entry_count:   u32,
    depth:         u32,
    return_flag:   u32,
    pending_count: u32,
    return_prog:   u8,
    name_ready:    u8,
    q_remaining:   u16,
    a_remaining:   u16,
    cur_name_len:  u16,
    answer_idx:    u16,
    name_buf:      [u8; DNS_NAME_BUF],
    pending:       [PendingLabel; DNS_MAX_ENTRIES],
    cache:         [CacheEntry; DNS_MAX_ENTRIES],
    stack:         [Frame; DNS_MAX_DEPTH],
}

// Mirror of `dns_event_t` from src/bpf/dns_parser.h. One record (A or AAAA)
// the parser emitted into the `events` ring buffer.
const DNS_MAX_NAME_LEN: usize = 255;

#[repr(C)]
#[derive(Clone, Copy)]
struct DnsEvent {
    qtype:      u16,
    name_len:   u16,
    txid:       u16,
    answer_idx: u16,
    is_ipv6:    u8,
    _pad:       [u8; 3],
    ip4:        u32,
    ip6:        [u8; 16],
    ttl:        u32,
    name:       [u8; DNS_MAX_NAME_LEN + 1],
}

impl DnsEvent {
    /// The owner FQDN, trimmed to the recorded `name_len`.
    fn name(&self) -> String {
        let n = (self.name_len as usize).min(DNS_MAX_NAME_LEN);
        String::from_utf8_lossy(&self.name[..n]).into_owned()
    }
}

// Mirror of `dns_ip_key_t` from src/bpf/dns_parser.h (reverse cache key).
#[repr(C)]
#[derive(Clone, Copy)]
struct DnsIpKey {
    is_ipv6: u8,
    _pad:    [u8; 3],
    addr:    [u8; 16],
}

// Mirror of `dns_rev_value_t` from src/bpf/dns_parser.h (reverse cache value).
#[repr(C)]
#[derive(Clone, Copy)]
struct DnsRevValue {
    inserted_ns: u64,
    ttl:         u32,
    name_len:    u16,
    _pad:        u16,
    name:        [u8; DNS_MAX_NAME_LEN + 1],
}

impl DnsRevValue {
    fn name(&self) -> String {
        let n = (self.name_len as usize).min(DNS_MAX_NAME_LEN);
        String::from_utf8_lossy(&self.name[..n]).into_owned()
    }
}

/// Look up an IPv4 address in the `dns_reverse` cache, returning its value.
fn lookup_reverse_v4(skel: &DnsParserSkel<'_>, ip: [u8; 4]) -> Option<DnsRevValue> {
    let mut key = DnsIpKey {
        is_ipv6: 0,
        _pad:    [0; 3],
        addr:    [0; 16],
    };
    key.addr[..4].copy_from_slice(&ip);
    // SAFETY: DnsIpKey is repr(C) and mirrors the kernel key byte-for-byte.
    let key_bytes: &[u8] =
        unsafe { std::slice::from_raw_parts(&key as *const _ as *const u8, size_of::<DnsIpKey>()) };
    let raw = skel
        .maps
        .dns_reverse
        .lookup(key_bytes, MapFlags::ANY)
        .expect("lookup dns_reverse")?;
    assert!(raw.len() >= size_of::<DnsRevValue>());
    // SAFETY: `raw` is at least as large as the struct, which mirrors the
    // kernel-side C layout. Unaligned read since `raw` is a Vec<u8>.
    Some(unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const DnsRevValue) })
}

/// Drains the `events` ring buffer one `DnsEvent` at a time.
///
/// libbpf's ring buffer only exposes a callback-driven `consume`, so we attach
/// a callback that pushes every record into a queue, then hand them back one by
/// one via [`EventReader::next_event`]. The reader lazily consumes the kernel
/// buffer when the queue runs dry, so `next_event` returns `None` once the ring
/// buffer holds nothing more.
struct EventReader<'a> {
    rb:    RingBuffer<'a>,
    queue: Rc<RefCell<VecDeque<DnsEvent>>>,
}

impl<'a> EventReader<'a> {
    fn new(skel: &'a DnsParserSkel<'a>) -> Self {
        let queue: Rc<RefCell<VecDeque<DnsEvent>>> = Rc::new(RefCell::new(VecDeque::new()));
        let sink = queue.clone();

        let mut builder = RingBufferBuilder::new();
        builder
            .add(&skel.maps.events, move |data: &[u8]| -> i32 {
                if data.len() >= size_of::<DnsEvent>() {
                    // SAFETY: `data` is at least as large as the struct, which
                    // mirrors the kernel-side C layout. Unaligned read since the
                    // ring buffer hands us an arbitrarily-aligned slice.
                    let ev: DnsEvent =
                        unsafe { std::ptr::read_unaligned(data.as_ptr() as *const DnsEvent) };
                    sink.borrow_mut().push_back(ev);
                }
                0
            })
            .expect("ringbuf add events");
        let rb = builder.build().expect("ringbuf build");

        Self { rb, queue }
    }

    /// Return the next `DnsEvent` from the ring buffer, or `None` if it is
    /// empty. Newly available records are consumed on demand.
    fn next_event(&self) -> Option<DnsEvent> {
        if self.queue.borrow().is_empty() {
            self.rb.consume().expect("consume events ring buffer");
        }
        self.queue.borrow_mut().pop_front()
    }
}

// captured from live traffic (txid=0x1925): query for config.extension.grammarly.com,
// answered by a CNAME to d27xxe7juh1us6.cloudfront.net plus four A records (and an OPT
// record in the additional section). Answer owner names use compression pointers.
const DNS_RESPONSE: [u8; 166] = [
   0x19, 0x25, 0x81, 0x80, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01,
            0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x09, 0x65, 0x78, 0x74, 0x65,
            0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x09, 0x67, 0x72, 0x61, 0x6d, 0x6d, 0x61,
            0x72, 0x6c, 0x79, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
            0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7a, 0x00, 0x1f,
            0x0e, 0x64, 0x32, 0x37, 0x78, 0x78, 0x65, 0x37, 0x6a, 0x75, 0x68, 0x31,
            0x75, 0x73, 0x36, 0x0a, 0x63, 0x6c, 0x6f, 0x75, 0x64, 0x66, 0x72, 0x6f,
            0x6e, 0x74, 0x03, 0x6e, 0x65, 0x74, 0x00, 0xc0, 0x3c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x0d, 0xe0, 0xf5, 0x6c, 0xc0,
            0x3c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x0d,
            0xe0, 0xf5, 0x7b, 0xc0, 0x3c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
            0x1c, 0x00, 0x04, 0x0d, 0xe0, 0xf5, 0x3d, 0xc0, 0x3c, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x04, 0x0d, 0xe0, 0xf5, 0x4e, 0x00,
            0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
];

/// A loaded skeleton plus the bookkeeping needed to drive test runs.
struct Harness {
    obj: Box<std::mem::MaybeUninit<libbpf_rs::OpenObject>>,
}

impl Harness {
    fn new() -> Self {
        Self {
            obj: Box::new(std::mem::MaybeUninit::uninit()),
        }
    }

    /// Open + load the skeleton and wire the tail-call jump table, mirroring
    /// the main binary in `main.rs`. Returns the loaded skeleton.
    fn load(&mut self) -> DnsParserSkel<'_> {
        let builder = DnsParserSkelBuilder::default();
        let mut open_skel = builder.open(&mut self.obj).expect("open skeleton");

        // Always enable BPF debug logging in tests
        if let Some(rodata) = open_skel.maps.rodata_data.as_mut() {
            rodata.debug = true;
        }

        let skel = open_skel.load().expect("load skeleton");

        let tail_calls = [
            (PROG_PARSE_FQDN, skel.progs.xdp_dns_parse_fqdn.as_fd()),
            (PROG_WALK_QUESTION, skel.progs.xdp_dns_walk_question.as_fd()),
            (PROG_WALK_ANSWER, skel.progs.xdp_dns_walk_answer.as_fd()),
            (PROG_EMIT_EVENTS, skel.progs.xdp_dns_emit_events.as_fd()),
        ];
        for (idx, prog_fd) in tail_calls {
            let key = idx.to_ne_bytes();
            let val = (prog_fd.as_raw_fd() as u32).to_ne_bytes();
            skel.maps
                .jmp_table
                .update(&key, &val, MapFlags::ANY)
                .expect("jmp_table := tail-call program");
        }

        skel
    }
}

/// Run `xdp_dns_ingress` against `packet`, returning the XDP action.
///
/// Note: the XDP `BPF_PROG_TEST_RUN` path rejects `BPF_F_TEST_RUN_ON_CPU`, so
/// the program executes on whatever CPU services the syscall. We therefore
/// scan every per-CPU state slot in `read_state` to find the one it wrote.
fn run_ingress(skel: &DnsParserSkel<'_>, packet: &[u8]) -> u32 {
    let input = libbpf_rs::ProgramInput {
        data_in: Some(packet),
        ..Default::default()
    };
    let output = skel
        .progs
        .xdp_dns_ingress
        .test_run(input)
        .expect("BPF_PROG_TEST_RUN(xdp_dns_ingress)");
    output.return_value
}

/// Read the parser state written by the program.
///
/// The program runs on a single (unknown) CPU, so we return the per-CPU slot
/// it populated (`id != 0`); if no slot was written we return a zeroed state.
fn read_state(skel: &DnsParserSkel<'_>) -> DnsParserState {
    let key = 0u32.to_ne_bytes();
    let per_cpu = skel
        .maps
        .state_map
        .lookup_percpu(&key, MapFlags::ANY)
        .expect("lookup state_map")
        .expect("state_map[0] present");

    let mut result: Option<DnsParserState> = None;
    for raw in &per_cpu {
        assert!(
            raw.len() >= size_of::<DnsParserState>(),
            "state value ({} bytes) smaller than DnsParserState ({} bytes)",
            raw.len(),
            size_of::<DnsParserState>()
        );
        // SAFETY: `raw` is at least as large as the struct, which mirrors the
        // kernel-side C layout. Use an unaligned read since `raw` is a Vec<u8>.
        let st: DnsParserState =
            unsafe { std::ptr::read_unaligned(raw.as_ptr() as *const DnsParserState) };
        if st.id != 0 {
            return st;
        }
        result.get_or_insert(st);
    }
    result.expect("state_map has at least one CPU slot")
}

/// Extract the FQDN the parser assembled in `name_buf`.
///
/// The parser writes a `.` after every literal label, including the final one,
/// and no longer NUL-terminates the name (the suffix cache, not `name_buf`, is
/// the real output). We read up to the first NUL left by the per-CPU map's
/// zeroing / label over-copy, then drop the single trailing `.` to recover the
/// logical name — exactly the span the cache `len` accounts for.
fn fqdn(state: &DnsParserState) -> String {
    let end = state
        .name_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(state.name_buf.len());
    let mut s = String::from_utf8_lossy(&state.name_buf[..end]).into_owned();
    if s.ends_with('.') {
        s.pop();
    }
    s
}

/// The suffix-cache entries `finalize` produced (the first `entry_count`).
fn cache_entries(state: &DnsParserState) -> &[CacheEntry] {
    let n = (state.entry_count as usize).min(DNS_MAX_ENTRIES);
    &state.cache[..n]
}

/// Reconstruct the `name_buf` window a cache entry points at.
fn name_window(state: &DnsParserState, entry: &CacheEntry) -> String {
    let start = entry.start as usize;
    let end = start + entry.len as usize;
    String::from_utf8_lossy(&state.name_buf[start..end]).into_owned()
}

/// Encode a dotted domain name into DNS wire-format labels.
fn encode_qname(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    out
}

/// Build an Ethernet/IPv4/UDP/DNS query packet for `qname`.
///
/// `dst_port` selects the UDP destination port. The packet is padded so the
/// parser's "63 bytes of headroom per label" bounds checks always pass.
fn build_dns_query(txid: u16, qname: &str, qdcount: u16, ancount: u16, dst_port: u16) -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&txid.to_be_bytes()); // id
    dns.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    dns.extend_from_slice(&qdcount.to_be_bytes());
    dns.extend_from_slice(&ancount.to_be_bytes());
    dns.extend_from_slice(&0u16.to_be_bytes()); // nscount
    dns.extend_from_slice(&0u16.to_be_bytes()); // arcount
    dns.extend_from_slice(&encode_qname(qname));
    dns.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    dns.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
                                                // Headroom so `src + 63 <= data_end` holds for every literal label.
    dns.extend_from_slice(&[0u8; 96]);

    let udp_len = (8 + dns.len()) as u16;

    let mut udp = Vec::new();
    udp.extend_from_slice(&40000u16.to_be_bytes()); // source port
    udp.extend_from_slice(&dst_port.to_be_bytes()); // dest port
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    udp.extend_from_slice(&dns);

    let total_len = (20 + udp.len()) as u16;

    let mut ip = Vec::new();
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // dscp/ecn
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64); // ttl
    ip.push(17); // protocol UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    ip.extend_from_slice(&[192, 168, 1, 10]); // src
    ip.extend_from_slice(&[192, 168, 1, 1]); // dst
    ip.extend_from_slice(&udp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // dst mac
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // src mac
    eth.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
    eth.extend_from_slice(&ip);

    eth
}

/// Wrap a raw DNS payload in Ethernet/IPv4/UDP headers, mirroring
/// `build_dns_query`'s framing but for the *response* direction.
///
/// A DNS response arrives with UDP source port 53 (the server) and is destined
/// for the client's ephemeral port. `dns_payload` is the complete DNS message
/// (header + question(s) + answer(s)); it is padded with the same 96 bytes of
/// headroom so the parser's "63 bytes per label" bounds checks always pass.
fn build_dns_response(dns_payload: &[u8]) -> Vec<u8> {
    let mut dns = dns_payload.to_vec();
    // Headroom so `src + 63 <= data_end` holds for every literal label.
    dns.extend_from_slice(&[0u8; 96]);

    let udp_len = (8 + dns.len()) as u16;

    let mut udp = Vec::new();
    udp.extend_from_slice(&53u16.to_be_bytes()); // source port (DNS server)
    udp.extend_from_slice(&40000u16.to_be_bytes()); // dest port (client)
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    udp.extend_from_slice(&dns);

    let total_len = (20 + udp.len()) as u16;

    let mut ip = Vec::new();
    ip.push(0x45); // version 4, IHL 5
    ip.push(0x00); // dscp/ecn
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    ip.extend_from_slice(&0u16.to_be_bytes()); // flags/frag
    ip.push(64); // ttl
    ip.push(17); // protocol UDP
    ip.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    ip.extend_from_slice(&[192, 168, 1, 1]); // src (server)
    ip.extend_from_slice(&[192, 168, 1, 10]); // dst (client)
    ip.extend_from_slice(&udp);

    let mut eth = Vec::new();
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst mac (client)
    eth.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src mac (server)
    eth.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
    eth.extend_from_slice(&ip);

    eth
}

#[test]
fn state_layout_matches_kernel_struct() {
    // dns_parser_state_t: 52 bytes of scalars, the 512-byte name buffer, then
    // pending[256] (4B each) and cache[256] (6B each), plus 4 bytes of tail
    // padding to the struct's 8-byte alignment.
    assert_eq!(size_of::<PendingLabel>(), 4);
    assert_eq!(size_of::<CacheEntry>(), 6, "u16,u16,u8 + 1 byte tail pad");
    assert_eq!(align_of::<CacheEntry>(), 2);
    assert_eq!(align_of::<Frame>(), 2);
    assert_eq!(align_of::<DnsParserState>(), 8, "u64 cursor sets alignment");
    assert_eq!(
        size_of::<DnsParserState>(),
        60 + DNS_NAME_BUF
            + DNS_MAX_ENTRIES * size_of::<PendingLabel>()
            + DNS_MAX_ENTRIES * size_of::<CacheEntry>()
            + DNS_MAX_DEPTH * size_of::<Frame>()
            + 4
    );
}

#[test]
fn parses_simple_fqdn() {
    let mut harness = Harness::new();
    let skel = harness.load();

    let packet = build_dns_query(0xBEEF, "example.com", 1, 0, 53);
    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS, "ingress should pass the packet");

    let st = read_state(&skel);
    assert_eq!(st.id, 0xBEEF, "transaction id");
    assert_eq!(st.qcount, 1, "qdcount");
    assert_eq!(st.acount, 0, "ancount");
    // `name_complete` resets `return_flag` to 0 for the next name; the recorded
    // length is the durable proof the root label terminated the parse.
    assert_eq!(st.cur_name_len, 11, "recorded assembled name length");
    assert_eq!(fqdn(&st), "example.com");
}

#[test]
fn parses_multi_label_fqdn() {
    let mut harness = Harness::new();
    let skel = harness.load();

    let packet = build_dns_query(0x0042, "www.google.com", 1, 2, 53);
    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS);

    let st = read_state(&skel);
    assert_eq!(st.id, 0x0042);
    assert_eq!(st.qcount, 1);
    assert_eq!(st.acount, 2);
    assert_eq!(fqdn(&st), "www.google.com");

    // Three labels => three suffix entries (full name, then each suffix).
    assert_eq!(st.entry_count, 3, "one cache entry per label");
    let entries = cache_entries(&st);
    assert_eq!(
        entries[0],
        CacheEntry {
            offset: 12,
            start:  0,
            len:    14,
        }
    );
    assert_eq!(
        entries[1],
        CacheEntry {
            offset: 16,
            start:  4,
            len:    10,
        }
    );
    assert_eq!(
        entries[2],
        CacheEntry {
            offset: 23,
            start:  11,
            len:    3,
        }
    );
    assert_eq!(name_window(&st, &entries[0]), "www.google.com");
    assert_eq!(name_window(&st, &entries[1]), "google.com");
    assert_eq!(name_window(&st, &entries[2]), "com");
}

#[test]
fn builds_suffix_cache() {
    // `finalize` records one suffix per label: the whole name plus every
    // shorter suffix, each keyed by its DNS-relative label offset.
    let mut harness = Harness::new();
    let skel = harness.load();

    // Standard 12-byte DNS header; the QNAME starts immediately after it.
    let packet = build_dns_query(0xABCD, "example.com", 1, 0, 53);
    assert_eq!(run_ingress(&skel, &packet), XDP_PASS);

    let st = read_state(&skel);
    assert_eq!(fqdn(&st), "example.com");
    assert_eq!(st.pending_count, 0, "finalize drains the pending list");
    assert_eq!(st.entry_count, 2, "two labels => two suffix entries");

    let entries = cache_entries(&st);
    // entry 0: "example.com" (11 bytes); label length byte at DNS offset 12.
    assert_eq!(
        entries[0],
        CacheEntry {
            offset: 12,
            start:  0,
            len:    11,
        }
    );
    // entry 1: suffix "com" (3 bytes); label length byte at DNS offset 20.
    assert_eq!(
        entries[1],
        CacheEntry {
            offset: 20,
            start:  8,
            len:    3,
        }
    );

    // The recorded windows must reconstruct the right substrings.
    assert_eq!(name_window(&st, &entries[0]), "example.com");
    assert_eq!(name_window(&st, &entries[1]), "com");
}

#[test]
fn matches_dns_source_port() {
    // The program matches when *either* UDP port is 53; here only the source
    // port is 53 (a DNS response direction).
    let mut harness = Harness::new();
    let skel = harness.load();

    let mut packet = build_dns_query(0x0001, "a.com", 1, 0, 53);
    // Rewrite UDP source port (eth14 + ip20 = offset 34) to 53 and dest to 40000.
    let udp = 14 + 20;
    packet[udp..udp + 2].copy_from_slice(&53u16.to_be_bytes());
    packet[udp + 2..udp + 4].copy_from_slice(&40000u16.to_be_bytes());

    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS);

    let st = read_state(&skel);
    assert_eq!(fqdn(&st), "a.com");
}

#[test]
fn ignores_non_dns_udp() {
    // UDP to a non-DNS port must be passed without touching parser state.
    let mut harness = Harness::new();
    let skel = harness.load();

    let packet = build_dns_query(0x1234, "example.com", 1, 0, 12345);
    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS);

    let st = read_state(&skel);
    assert_eq!(st.id, 0, "non-DNS packet must not seed parser state");
    assert_eq!(st.qcount, 0);
    assert_eq!(fqdn(&st), "");
}

#[test]
fn ignores_non_ip_ethertype() {
    // ARP (0x0806) must be passed through untouched.
    let mut harness = Harness::new();
    let skel = harness.load();

    let mut packet = build_dns_query(0x5555, "example.com", 1, 0, 53);
    packet[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS);

    let st = read_state(&skel);
    assert_eq!(st.id, 0, "non-IP packet must not seed parser state");
}

#[test]
fn parses_dns_response() {
    let mut harness = Harness::new();
    let skel = harness.load();

    // The events ring buffer must be attached before the program runs so the
    // record submitted during `test_run` is waiting for us to consume.
    let reader = EventReader::new(&skel);

    let packet = build_dns_response(&DNS_RESPONSE);
    let action = run_ingress(&skel, &packet);
    assert_eq!(action, XDP_PASS, "ingress should pass the packet");

    // The CNAME answer (record 0) is skipped; the four A records that follow
    // are all owned by the CNAME target d27xxe7juh1us6.cloudfront.net.
    let expected_ips = [
        [13, 224, 245, 108],
        [13, 224, 245, 123],
        [13, 224, 245, 61],
        [13, 224, 245, 78],
    ];

    for (i, ip) in expected_ips.iter().enumerate() {
        let ev = reader
            .next_event()
            .unwrap_or_else(|| panic!("expected A answer {} in the ring buffer", i + 1));
        assert_eq!(ev.txid, 0x1925, "transaction id");
        assert_eq!(ev.qtype, 1, "A record type");
        // answer_idx counts every record, so the four A records are 1..=4
        // (the leading CNAME is record 0).
        assert_eq!(ev.answer_idx as usize, i + 1, "answer index");
        assert_eq!(ev.is_ipv6, 0, "A => IPv4 address valid");
        assert_eq!(ev.name(), "d27xxe7juh1us6.cloudfront.net");
        assert_eq!(ev.name_len as usize, "d27xxe7juh1us6.cloudfront.net".len());
        assert_eq!(ev.ttl, 28, "answer TTL");
        // ip4 holds the wire bytes in network order; to_ne_bytes recovers them.
        assert_eq!(ev.ip4.to_ne_bytes(), *ip, "A record address");
    }

    // The ring buffer held exactly the four A answers; the next read drains nothing.
    assert!(
        reader.next_event().is_none(),
        "ring buffer should be empty after the four A answers"
    );
}

#[test]
fn caches_reverse_addresses() {
    // The same grammarly response should populate the reverse cache: each of the
    // four A answers writes an `address -> name` entry keyed by the resolved IP.
    let mut harness = Harness::new();
    let skel = harness.load();

    let packet = build_dns_response(&DNS_RESPONSE);
    assert_eq!(run_ingress(&skel, &packet), XDP_PASS, "ingress should pass");

    let expected_ips = [
        [13, 224, 245, 108],
        [13, 224, 245, 123],
        [13, 224, 245, 61],
        [13, 224, 245, 78],
    ];

    for ip in &expected_ips {
        let v = lookup_reverse_v4(&skel, *ip)
            .unwrap_or_else(|| panic!("reverse cache missing entry for {ip:?}"));
        assert_eq!(v.name(), "d27xxe7juh1us6.cloudfront.net", "cached owner name");
        assert_eq!(
            v.name_len as usize,
            "d27xxe7juh1us6.cloudfront.net".len(),
            "cached name length"
        );
        assert_eq!(v.ttl, 28, "cached TTL");
        assert_ne!(v.inserted_ns, 0, "inserted_ns stamped");
    }
}
