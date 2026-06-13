use std::collections::BTreeMap;
use std::ffi::CString;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context, Result};
use flexi_logger::{Duplicate, FileSpec, Logger};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::{MapCore, RingBufferBuilder};
use log::{debug, error, info};

mod dns_parser {
    include!("bpf/dns_parser.skel.rs");
}
use dns_parser::*;

#[cfg(test)]
mod tests;

// keep in sync with the PROG_* indices in dns_parser.h
const PROG_PARSE_FQDN: u32 = 0;
const PROG_WALK_QUESTION: u32 = 1;
const PROG_WALK_ANSWER: u32 = 2;
const PROG_EMIT_EVENTS: u32 = 3;

use libbpf_rs::XdpFlags;

// Mirror of dns_event_t from dns_parser.h. Keep field order and types in sync.
const DNS_MAX_NAME_LEN: usize = 255;

#[repr(C)]
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

// Mirror of dns_ip_key_t from dns_parser.h (the reverse cache key).
#[repr(C)]
struct DnsIpKey {
    is_ipv6: u8,
    _pad:    [u8; 3],
    addr:    [u8; 16],
}

// Mirror of dns_rev_value_t from dns_parser.h (the reverse cache value).
#[repr(C)]
struct DnsRevValue {
    inserted_ns: u64,
    ttl:         u32,
    name_len:    u16,
    _pad:        u16,
    name:        [u8; DNS_MAX_NAME_LEN + 1],
}

/// CLOCK_MONOTONIC nanoseconds, matching the kernel's `bpf_ktime_get_ns`.
fn monotonic_now_ns() -> u64 {
    let mut ts = unsafe { std::mem::zeroed::<libc::timespec>() };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// Dump the in-kernel reverse cache (address -> name), skipping expired entries.
fn dump_cache(skel: &DnsParserSkel) -> Result<()> {
    let now = monotonic_now_ns();
    let mut count = 0u64;
    info!("reverse DNS cache (address -> name):");
    for key in skel.maps.dns_reverse.keys() {
        let Some(val) = skel
            .maps
            .dns_reverse
            .lookup(&key, libbpf_rs::MapFlags::ANY)
            .context("lookup dns_reverse")?
        else {
            continue; // evicted between keys() and lookup()
        };
        if key.len() < size_of::<DnsIpKey>() || val.len() < size_of::<DnsRevValue>() {
            continue;
        }
        let k: DnsIpKey = unsafe { std::ptr::read_unaligned(key.as_ptr() as *const DnsIpKey) };
        let v: DnsRevValue =
            unsafe { std::ptr::read_unaligned(val.as_ptr() as *const DnsRevValue) };

        let age = now.saturating_sub(v.inserted_ns);
        if age > v.ttl as u64 * 1_000_000_000 {
            continue; // expired -> treat as a miss
        }

        let addr = if k.is_ipv6 != 0 {
            Ipv6Addr::from(k.addr).to_string()
        } else {
            Ipv4Addr::from([k.addr[0], k.addr[1], k.addr[2], k.addr[3]]).to_string()
        };
        let name_len = (v.name_len as usize).min(DNS_MAX_NAME_LEN);
        let name = String::from_utf8_lossy(&v.name[..name_len]);
        info!("  {addr} -> {name} (ttl={}s, age={}s)", v.ttl, age / 1_000_000_000);
        count += 1;
    }
    info!("{count} live entr{}", if count == 1 { "y" } else { "ies" });
    Ok(())
}

fn print_dns_event(data: &[u8]) {
    if data.len() < size_of::<DnsEvent>() {
        return;
    }
    let ev: DnsEvent = unsafe { std::ptr::read_unaligned(data.as_ptr() as *const DnsEvent) };
    let name_len = (ev.name_len as usize).min(DNS_MAX_NAME_LEN);
    let name = String::from_utf8_lossy(&ev.name[..name_len]);
    let (record_type, addr) = if ev.is_ipv6 != 0 {
        ("AAAA", Ipv6Addr::from(ev.ip6).to_string())
    } else {
        ("A", Ipv4Addr::from(ev.ip4.to_ne_bytes()).to_string())
    };
    info!(
        "[txid={} answer={}] {} {} {} ttl={}",
        ev.txid, ev.answer_idx, name, record_type, addr, ev.ttl
    );
}

struct Capture {
    qdcount: u16,
    ancount: u16,
    payload: Vec<u8>,
}

fn format_payload(payload: &[u8]) -> String {
    // 12 bytes per line, matching the DNS_RESPONSE style in tests.rs
    let lines: Vec<String> = payload
        .chunks(12)
        .map(|chunk| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("0x{b:02x}")).collect();
            format!("            {}", hex.join(", "))
        })
        .collect();
    lines.join(",\n")
}

fn write_payloads(path: &str, entries: &BTreeMap<String, Capture>) {
    let mut out = String::from("{\n    \"payloads\": {\n");
    let mut first = true;
    for (key, cap) in entries {
        if !first {
            out.push_str(",\n");
        }
        first = false;
        out.push_str(&format!("        \"{key}\": {{\n"));
        out.push_str(&format!("            \"questions\": {},\n", cap.qdcount));
        out.push_str(&format!("            \"answers\": {},\n", cap.ancount));
        out.push_str("            \"payload\": [\n");
        out.push_str(&format_payload(&cap.payload));
        out.push_str("\n            ]\n");
        out.push_str("        }");
    }
    out.push_str("\n    }\n}\n");
    if let Err(e) = std::fs::write(path, &out) {
        error!("write {path}: {e}");
    }
}

fn if_nametoindex(name: &str) -> Result<u32> {
    let cname = CString::new(name)?;
    let idx = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if idx == 0 {
        bail!(
            "if_nametoindex({name}): {}",
            std::io::Error::last_os_error()
        );
    }
    Ok(idx)
}

fn main() -> Result<()> {
    println!("dns-cache: a simple XDP-based DNS cache for testing and fuzzing");
    Logger::try_with_env_or_str("info")?
        .log_to_file(FileSpec::default().basename("dns-cache"))
        .duplicate_to_stderr(Duplicate::All)
        .start()?;

    let args: Vec<String> = std::env::args().collect();
    let mut ifname = None;
    let mut debug_enabled = false;
    let mut dump_only = false;

    for arg in args.iter().skip(1) {
        if arg == "-v" {
            debug_enabled = true;
        } else if arg == "--dump-cache" {
            dump_only = true;
        } else if ifname.is_none() {
            ifname = Some(arg);
        } else {
            eprintln!("too many arguments");
            eprintln!("usage: {} [-v] [--dump-cache] <iface>", args[0]);
            std::process::exit(1);
        }
    }

    // --dump-cache reuses the pinned reverse map populated by the attached
    // instance, so it does not need an interface.
    if !dump_only && ifname.is_none() {
        eprintln!("usage: {} [-v] [--dump-cache] <iface>", args[0]);
        std::process::exit(1);
    }

    let mut open_obj = std::mem::MaybeUninit::uninit();
    let builder = DnsParserSkelBuilder::default();
    let mut open_skel = builder
        .open(&mut open_obj)
        .context("failed to open skeleton")?;

    if debug_enabled {
        if let Some(rodata) = open_skel.maps.rodata_data.as_mut() {
            rodata.debug = true;
        }
    }

    let skel = open_skel.load().context("failed to load skeleton")?;

    // --dump-cache: load reuses the pinned reverse map, dump it, and exit
    // without attaching.
    if dump_only {
        dump_cache(&skel)?;
        return Ok(());
    }

    let ifname = ifname.expect("ifname required when not dumping");
    let ifindex = if_nametoindex(ifname)?;

    // Seed the tail-call program array: each parser stage is reachable from the
    // others via jmp_table[PROG_*].
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
            .update(&key, &val, libbpf_rs::MapFlags::ANY)
            .with_context(|| format!("jmp_table[{idx}] := tail-call program"))?;
    }

    // attach xdp_dns_ingress
    let prog_fd = skel.progs.xdp_dns_ingress.as_fd();
    let xdp = libbpf_rs::Xdp::new(prog_fd);
    xdp.attach(ifindex as i32, XdpFlags::UPDATE_IF_NOEXIST)
        .with_context(|| format!("bpf_xdp_attach({ifname})"))?;

    let captures: Arc<Mutex<BTreeMap<String, Capture>>> = Arc::new(Mutex::new(BTreeMap::new()));
    let captures_cb = captures.clone();

    let mut rb_builder = RingBufferBuilder::new();
    rb_builder
        .add(&skel.maps.dns_capture_rb, move |data: &[u8]| -> i32 {
            // txid(2) + cpu(2) + qdcount(2) + ancount(2) + len(2) + payload
            if data.len() < 10 {
                return 0;
            }
            let txid = u16::from_ne_bytes([data[0], data[1]]);
            let cpu = u16::from_ne_bytes([data[2], data[3]]);
            let qdcount = u16::from_ne_bytes([data[4], data[5]]);
            let ancount = u16::from_ne_bytes([data[6], data[7]]);
            let pay_len = u16::from_ne_bytes([data[8], data[9]]) as usize;
            let end = (10 + pay_len).min(data.len());
            let payload = data[10..end].to_vec();
            let key = format!("{txid}_{cpu}");
            let mut map = captures_cb.lock().unwrap();
            map.insert(
                key.clone(),
                Capture {
                    qdcount,
                    ancount,
                    payload,
                },
            );
            write_payloads("payloads.json", &map);
            debug!("captured {key} (q={qdcount} a={ancount} {pay_len} bytes)");
            0
        })
        .context("ringbuf add")?;
    rb_builder
        .add(&skel.maps.events, |data: &[u8]| -> i32 {
            print_dns_event(data);
            0
        })
        .context("events ringbuf add")?;
    let rb = rb_builder.build().context("ringbuf build")?;

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst))
            .context("set signal handler")?;
    }

    info!("attached xdp_dns_ingress to {ifname} (ifindex={ifindex}). Ctrl-C to detach.");

    while !stop.load(Ordering::SeqCst) {
        let _ = rb.poll(std::time::Duration::from_millis(200));
    }

    drop(rb);
    let _ = xdp.detach(ifindex as i32, XdpFlags::UPDATE_IF_NOEXIST);
    write_payloads("payloads.json", &captures.lock().unwrap());
    Ok(())
}

use std::os::fd::{AsFd, AsRawFd};
