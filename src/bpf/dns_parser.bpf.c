#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "dns_parser.h"

char _license[] SEC("license") = "GPL";

/* 
 * Global configuration. Set from user-space loader via skeleton rodata. 
 * 'volatile' prevents the compiler from optimizing away the check.
 */
volatile const bool debug = false;

#define bpf_printk0(fmt, ...) \
    do { \
        if (debug) \
            bpf_printk(fmt, ##__VA_ARGS__); \
    } while (0)

typedef struct dns_hdr {
    u16 id;
    u16 flags;
    u16 qdcount;
    u16 ancount;
    u16 nscount;
    u16 arcount;
} PACKED dns_hdr_t;


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, dns_parser_state_t);
} state_map  SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 3);    // PROG_PARSE_FQDN, PROG_WALK_QUESTION, PROG_WALK_ANSWER
    __type(key, u32);
    __type(value, u32);
} jmp_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);   // 256 KB
} dns_capture_rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


static __always_inline dns_parser_state_t *get_state(void)
{
    u32 k = 0;
    return bpf_map_lookup_elem(&state_map, &k);
}


#define PARSER_ERROR(cond, err_code) \
    do { \
        if (cond) { \
            err = err_code; \
            goto error; \
        } \
    } while (0)


#define BARRIER(var)  asm volatile("" : "+r"(var));


static __always_inline void finalize(dns_parser_state_t *st)
{
    u16 name_end = st->cursor;
    if (name_end > 0) 
        name_end -= 1;  // exclude trailing '.'

    for (int i = 0; i < DNS_MAX_ENTRIES; i++) 
    {
        if (i >= st->pending_count)
            break;
        pending_label_t pl = st->pending[i];
        if (pl.start_cursor > name_end)
            continue;
        u16 len = (u16)(name_end - pl.start_cursor);
        u16 ec = st->entry_count;
        if (ec < DNS_MAX_ENTRIES && len <= DNS_MAX_NAME_LEN) {
            st->cache[ec].offset = pl.key_offset;
            st->cache[ec].start  = pl.start_cursor;
            st->cache[ec].len    = (u8)len;
            st->entry_count = ec + 1;
            //bpf_printk0("[dns-parser-%d]: entry %d, offset %d, start %d, len %d\n",
            //           st->id, ec, pl.key_offset, pl.start_cursor, len);
        }
    }

    for (int i = 0; i < DNS_MAX_DEPTH; i++) {
        if (st->depth == 0)
            break;
        __u8 d = st->depth - 1;
        if (d >= DNS_MAX_DEPTH)
            break;
        st->packet_offset = st->stack[d].return_offset;
        st->depth = d;
    }

    st->pending_count = 0;
}


// Called right after finalize when a name is fully assembled. Records The
// assembled name's length, then resets the per-name scratch so the next Name
// starts clean. The owner-name string for the current record lives in
// name_buf[name_start .. name_start + cur_name_len).
static __always_inline void name_complete(dns_parser_state_t *st)
{
    u32 clen = (st->cursor > st->name_start) ? st->cursor - st->name_start - 1 : 0;  // strip trailing '.'
    if (clen > DNS_MAX_NAME_LEN)
        clen = DNS_MAX_NAME_LEN;
    st->cur_name_len = (u16)clen;

    // next name appends after this one; reset per-name scratch
    st->name_start    = st->cursor;
    st->depth         = 0;
    st->return_flag   = 0;
    st->pending_count = 0;
}

// Cache lookup: linear scan, bounded. Returns 1 and fills *out on hit.
// Only finalized entries are matched (entry_count excludes in-progress
// frames), so a self-pointer can never read a half-built window. 
static __always_inline int cache_lookup(dns_parser_state_t *st,
                                        u16 target,
                                        cache_entry_t *out)
{
    u16 n = st->entry_count;
    for (int i = 0; i < DNS_MAX_ENTRIES; i++) {
        if (i >= n)
            break;
        if (st->cache[i].offset == target) {
            *out = st->cache[i];
            return 1;
        }
    }
    return 0;
}


SEC("xdp")
int xdp_dns_ingress(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    /* IHL is in 32-bit words; honor it so options don't desync the offset. */
    u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (udp->source != bpf_htons(DNS_PORT) && udp->dest != bpf_htons(DNS_PORT))
        return XDP_PASS;

    dns_hdr_t *dns = (void *)(udp + 1);
    if ((void *)(dns + 1) > data_end)
        return XDP_PASS;

    dns_parser_state_t *st = get_state();
    if (!st)
        return XDP_PASS;

    u16 qdcount = bpf_ntohs(dns->qdcount);
    u16 ancount = bpf_ntohs(dns->ancount);

    {
        u32 pay_len = (u32)(data_end - (void *)dns);
        if (pay_len >= DNS_PAYLOAD_MAX)
            pay_len = DNS_PAYLOAD_MAX - 1;
        BARRIER(pay_len);
        pay_len &= (DNS_PAYLOAD_MAX - 1);  // prove [0, 511] to verifier
        dns_capture_t *cap = bpf_ringbuf_reserve(&dns_capture_rb, sizeof(dns_capture_t), 0);
        if (cap) {
            cap->txid    = bpf_ntohs(dns->id);
            cap->cpu     = bpf_get_smp_processor_id();
            cap->qdcount = qdcount;
            cap->ancount = ancount;
            cap->len     = (u16)pay_len;
            bpf_probe_read_kernel(cap->payload, pay_len, dns);
            bpf_ringbuf_submit(cap, 0);
        }
    }

    u32 dns_base = (u32)((void *)dns - data);
    st->id            = bpf_ntohs(dns->id);
    st->qcount        = qdcount;
    st->acount        = ancount;
    st->cpu           = bpf_get_smp_processor_id();
    st->dns_base      = dns_base;
    st->packet_offset = dns_base + (u32)sizeof(dns_hdr_t); // first QNAME
    st->cursor        = 0;
    st->name_start    = 0;
    st->entry_count   = 0;
    st->depth         = 0;
    st->return_flag   = 0;
    st->q_remaining  = qdcount;
    st->a_remaining  = ancount;
    st->answer_idx   = 0;

    bpf_printk0("[dns-parser-%d/%d] flags=0x%04x qd=%d an=%d\n",
               st->id, st->cpu, bpf_ntohs(dns->flags), st->qcount, st->acount);

    if (st->q_remaining > 0) 
    {
        st->return_prog = PROG_WALK_QUESTION;
        bpf_tail_call(ctx, &jmp_table, PROG_PARSE_FQDN);
    } 
    else 
    {
        bpf_tail_call(ctx, &jmp_table, PROG_WALK_ANSWER);
    }
   

    bpf_printk0("[dns-parser-%d] tail call failed\n", st->id);

    return XDP_PASS;
}

SEC("xdp")
int xdp_dns_parse_fqdn(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    dns_parser_error_e err = DNS_PARSE_SUCCESS;

    dns_parser_state_t *st = get_state();
    PARSER_ERROR (st == NULL, 
            DNS_PARSE_ERR_NO_STATE);


    #pragma clang loop unroll(full)
    for (int i = 0; i < 8; i++)
    {
        u32 off = st->packet_offset;
        PARSER_ERROR (off > 0x3FFF, 
                DNS_PARSE_ERR_INVALID_OFFSET);

        u8 *cur = (u8 *)data + off;
        PARSER_ERROR (cur + 1 > (u8 *)data_end, 
                DNS_PARSE_ERR_OUT_OF_BOUNDS);

        u8 len = *cur;
        if (len == 0x00)
        {
            st->return_flag = 1;
            st->packet_offset = off + 1;
            finalize(st);
            name_complete(st);
            bpf_printk0("[dns-parser-%d/%d] parse_fqdn: fqdn=%s\n", st->id, st->cpu, st->name_buf);
            bpf_tail_call(ctx, &jmp_table, st->return_prog);
            return XDP_PASS;
        }

        if ((len & DNS_LABEL_MASK) == DNS_PTR_BITS)
        {
            if (data + off + 2 > data_end)
                return XDP_PASS;

            u8 b2 = *((u8 *)(data + off + 1));
            u16 target = (u16)(((len & 0x3F) << 8) | b2);

            cache_entry_t hit;
            if (cache_lookup(st, target, &hit)) 
            {
                if (hit.len <= DNS_MAX_NAME_LEN &&
                    st->cursor + hit.len + 1 <= DNS_NAME_BUF &&
                    hit.start + hit.len <= DNS_NAME_BUF) {
                    #pragma unroll
                    for (int j = 0; j < DNS_MAX_NAME_LEN; j++) {
                        if (j >= hit.len)
                            break;
                        u32 si = (u32)hit.start + (u32)j;
                        u32 di = (u32)st->cursor + (u32)j;
                        if (si >= DNS_NAME_BUF || di >= DNS_NAME_BUF)
                            break;
                        BARRIER(si);
                        BARRIER(di);
                        st->name_buf[di & (DNS_NAME_BUF - 1)] = st->name_buf[si & (DNS_NAME_BUF - 1)];
                    }
                    st->cursor += hit.len;
                    u64 dot_idx = st->cursor;
                    BARRIER(dot_idx);
                    if (dot_idx < DNS_NAME_BUF)
                        st->name_buf[dot_idx & (DNS_NAME_BUF - 1)] = '.';
                    st->cursor += 1;
                }
                st->packet_offset = off + 2;
                finalize(st);
                name_complete(st);
                bpf_tail_call(ctx, &jmp_table, st->return_prog);
            }

            PARSER_ERROR (st->depth >= DNS_MAX_DEPTH, 
                    DNS_PARSE_ERR_MAX_DEPTH);

            u8 d = st->depth;
            if (d < DNS_MAX_DEPTH) 
            {
                st->stack[d].return_offset = (u16)(off+2);
                st->stack[d].start_cursor = (u16)st->cursor;
                st->stack[d].key_offset = (u16)(off - st->dns_base);
                st->depth = d + 1;
            }

            st->packet_offset = st->dns_base + (target & DNS_PTR_OFFSET);

            bpf_tail_call(ctx, &jmp_table, PROG_PARSE_FQDN);

            return XDP_PASS;
        }

        PARSER_ERROR ((len & DNS_LABEL_MASK) != DNS_LITERAL_BITS, 
                DNS_PARSE_ERR_INVALID_LITERAL_BITS);

        PARSER_ERROR (len > DNS_MAX_LABEL_LEN, 
                DNS_PARSE_ERR_LABEL_TOO_LONG);

        u8 *src = cur + 1;

        // Packet Safety: Prove we have at least 63 bytes available to safely overcopy
        PARSER_ERROR (src + DNS_MAX_LABEL_LEN > (u8 *)data_end, 
                DNS_PARSE_ERR_INVALID_LABEL_LEN);

        {
            u16 pc = st->pending_count;
            if (pc < DNS_MAX_ENTRIES)
            {
                st->pending[pc].key_offset = (u16)(off - st->dns_base);
                st->pending[pc].start_cursor = (u16)st->cursor;
                st->pending_count = pc + 1;
            }
        }

       // Map Safety: Isolate the index and prove writing 63 bytes won't exceed DNS_NAME_BUF
        u64 di = st->cursor;
        BARRIER(di);
        PARSER_ERROR (di > (DNS_NAME_BUF - 64),   
                DNS_PARSE_ERR_NAME_BUF_OVERFLOW);


         __builtin_memcpy(&st->name_buf[di & (DNS_NAME_BUF - 1)], src, DNS_MAX_LABEL_LEN);
        
        st->cursor += len;

        u64 loop_idx = st->cursor;
        BARRIER(loop_idx);
        if (loop_idx < DNS_NAME_BUF) {
            st->name_buf[loop_idx & (DNS_NAME_BUF - 1)] = '.';
        }

        st->cursor += 1;
        st->packet_offset = off + 1 + len;
    }

    return XDP_PASS;

error:
    if (st)
    {
        // print the src, the payload len, offset, and the error code for debugging
        bpf_printk0("[dns-parser-%d] parse_fqdn error: code=%d, src=%d, offset=%d, payload_len=%d\n",
                   st->id, err, st->packet_offset, (u32)(data_end - data));
    }
    else 
        bpf_printk0("[dns-parser-NONE] parse_fqdn error: %d (no state)\n", err);
    return XDP_PASS;
}

SEC("xdp")
int xdp_dns_walk_question(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    dns_parser_state_t *st = get_state();
    if (!st)
        return XDP_PASS;

    // skip QTYPE(2) + QCLASS(2) that follow the question name 
    u32 off = st->packet_offset;
    if (data + off + 4 > data_end)
        return XDP_PASS;
    st->packet_offset = off + 4;

    if (st->q_remaining > 0)
        st->q_remaining -= 1;

    bpf_printk0("[dns-parser-%d/%d] walk_question: q_remaining=%d\n", st->id, st->cpu, st->q_remaining);

    if (st->q_remaining > 0) 
    {
        st->return_prog = PROG_WALK_QUESTION;
        bpf_tail_call(ctx, &jmp_table, PROG_PARSE_FQDN);
        return XDP_PASS;
    }

    // questions done -> answers. Cache + name_buf are preserved: cache
    // windows point into the question bytes already in name_buf, and answer
    // owner names append after them, so hits into the question name stay valid.
    bpf_tail_call(ctx, &jmp_table, PROG_WALK_ANSWER);

    return XDP_PASS;
}

SEC("xdp")
int xdp_dns_walk_answer(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    dns_parser_state_t *st = get_state();
    if (!st)
        return XDP_PASS;


    if (st->a_remaining == 0)
    {
        bpf_printk0("[dns-parser-%d/%d] walk_answer: all answers processed\n", st->id, st->cpu);
        return XDP_PASS;
    }

    if (!st->name_ready)
    {
        bpf_printk0("[dns-parser-%d/%d] walk_answer: a_remaining=%d\n", st->id, st->cpu, st->a_remaining);
        st->name_ready = 1;
        st->return_prog = PROG_WALK_ANSWER;
        bpf_tail_call(ctx, &jmp_table, PROG_PARSE_FQDN);
        return XDP_PASS;
    }

    st->name_ready = 0;

    u32 off = st->packet_offset;
    // Bound the offset so the verifier keeps packet-range tracking across the
    // variable offset: find_good_pkt_pointers() drops the range when a packet
    // pointer's umax_value exceeds MAX_PACKET_OFF (0xffff). Without this the
    // base pointer keeps range=0 and the *(u16 *)(data + off + 8) read below is
    // rejected. The data_end checks still enforce the real packet bounds.
    if (off > 0x7fff)
        return XDP_PASS;


    if (data + off + 10 > data_end) // skip TYPE(2), CLASS(2), TTL(4), RDLENGTH(2)
        return XDP_PASS;

    u16 type = bpf_ntohs(*(u16 *)(data + off));
    u32 rdata = off + 10; // RDATA starts after the fixed fields

    // bpf_ntohs() (byte swap) leaves the verifier with an unbounded scalar, so
    // mask back to the u16 range before adding it to the packet pointer below
    // (otherwise the data + rdata + rdlen math is rejected: "unbounded min
    // value"). BARRIER() hides the value's provenance so the compiler can't
    // drop the mask as redundant.
    u32 rdlen = bpf_ntohs(*(u16 *)(data + off + 8));
    BARRIER(rdlen);
    rdlen &= 0xffff;

    if (data + rdata + rdlen > data_end)
        return XDP_PASS;

    u16 nl = st->cur_name_len;
    if (nl > DNS_MAX_NAME_LEN)
        nl = DNS_MAX_NAME_LEN;
    u32 ns = st->name_start- (nl + 1);

    if ((type == DNS_TYPE_A && rdlen == 4) ||
        (type == DNS_TYPE_AAAA && rdlen == 16))
    {
        dns_event_t *ev = bpf_ringbuf_reserve(&events, sizeof(dns_event_t), 0);
        if (ev)
        {
            ev->qtype      = type;
            ev->name_len   = nl;
            ev->txid       = st->id;
            ev->answer_idx = st->answer_idx;
            if (type == DNS_TYPE_A)
            {
                if (data + rdata + 4 > data_end)
                {
                    bpf_ringbuf_discard(ev, 0);
                    return XDP_PASS;
                }
                ev->is_ipv6 = 0;
                ev->ip4 = *(u32 *)(data + rdata);
                __builtin_memset(ev->ip6, 0, sizeof(ev->ip6));
            }
            else
            {
                if (data + rdata + 16 > data_end)
                {
                    bpf_ringbuf_discard(ev, 0);
                    return XDP_PASS;
                }
                ev->is_ipv6 = 1;
                ev->ip4 = 0;
                #pragma unroll
                for (int i = 0; i < 16; i++)
                    ev->ip6[i] = *((__u8 *)(data + rdata + i));
            }

            #pragma unroll
            for (int i = 0; i < DNS_MAX_NAME_LEN; i++) {
                if (i >= nl)
                    break;
                __u32 si = (__u32)ns + (__u32)i;
                if (si >= DNS_NAME_BUF)
                    break;
                BARRIER(si);
                ev->name[i] = st->name_buf[si & (DNS_NAME_BUF - 1)];
            }
            if (nl <= DNS_MAX_NAME_LEN)
                ev->name[nl] = '\0';
            bpf_ringbuf_submit(ev, 0);
        }
    }

    
    st->packet_offset = rdata + rdlen;
    st->answer_idx += 1;
    if (st->a_remaining > 0)
        st->a_remaining -= 1;

    // next record
    bpf_tail_call(ctx, &jmp_table, PROG_WALK_ANSWER);
    return XDP_PASS;
}



