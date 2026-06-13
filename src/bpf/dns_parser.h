#ifndef __DNS_PARSER_H
#define __DNS_PARSER_H  

#ifdef __bpf__
#include <vmlinux.h>
#else
typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
#endif /* __bpf__ */

#ifndef ETH_P_IP
#define ETH_P_IP            0x0800
#endif

#define PACKED __attribute__((packed))

#define DNS_PORT            53

// DNS record type values we resolve to addresses
#define DNS_TYPE_A          1
#define DNS_TYPE_CNAME      5
#define DNS_TYPE_AAAA       28


#define DNS_NAME_BUF        512     // UDP DNS payload ceiling

#define DNS_MAX_ENTRIES     256     // Max label-start offsets in a 512B packet

#define DNS_MAX_DEPTH       16

// RFC 1035 hard limits
#define DNS_MAX_NAME_LEN    255
#define DNS_MAX_LABEL_LEN   63

// Wire-format token classification
#define DNS_LABEL_MASK      0xC0    // top two bits of a length byte
#define DNS_PTR_BITS        0xC0    // 11 -> compression Pointer
#define DNS_LITERAL_BITS    0x00    // 00 -> literal label
#define DNS_PTR_OFFSET      0x3FFF  // low 14 bits of a pointer = target

// jump table (BPF_MAP_TYPE_PROG_ARRAY) indices
#define PROG_PARSE_FQDN     0    // assemble one name
#define PROG_WALK_QUESTION  1    // skip question names (seed cache), then answers
#define PROG_WALK_ANSWER    2    // walk answer records, buffer A/AAAA events
#define PROG_EMIT_EVENTS    3    // drain buffered events into the ring buffer


typedef struct cache_entry {
    u16 offset;   // KEY: DNS offset this suffix lives at
    u16 start;    // window start index into name_buf
    u8  len;      // window length in bytes
} cache_entry_t;

typedef struct pending_label {
    u16 key_offset;         // DNS offset this frame resolves (becomes cache key)
    u16 start_cursor;       // where this frame's suffix begins in name_buf
} pending_label_t;


typedef struct frame {
    u16 return_offset;      // packet offset where the parent resumes
    u16 start_cursor;       // where this frame's suffix begins in name_buf
    u16 key_offset;         // DNS offset this frame resolves (becomes cache key)
} frame_t;


typedef struct dns_parser_state {
    u16 id;                 // transaction id from DNS header
    u16 qcount;             // question count from DNS header (for validation)
    u16 acount;             // answer count from DNS header (for validation)
    u32 cpu;                // CPU that handled packet entry (verify tail calls stay put)
    u32 dns_base;           // absolute offset of DNS header start in the packet
    u32 packet_offset;      // absolute read cursor within packet data
    unsigned long long cursor;
    u32 name_start;
    u32 entry_count;
    u32 depth;
    u32 return_flag;        // 0 = descending, 1 = folding/terminated
    u32 pending_count;      // labels recorded on the current name's walk
                             
    // message walker state
    u8 return_prog;         // which walker parse_fqdn tail-calls back to
    u8  name_ready;         // 1 = just returned from parse_fqdn with a name
    u16 q_remaining;        // questions left to skip
    u16 a_remaining;        // answers left to walk
    u16 cur_name_len;       // length of the just-assembled name (for the walker)
    u16 answer_idx;         // 0-based index of the answer currently being emitted

    char name_buf[DNS_NAME_BUF]; 
    pending_label_t pending[DNS_MAX_ENTRIES];
    cache_entry_t   cache[DNS_MAX_ENTRIES];
    frame_t         stack[DNS_MAX_DEPTH];
} dns_parser_state_t;


#define DNS_PAYLOAD_MAX     512   // max bytes captured per DNS message

typedef struct dns_capture {
    u16 txid;
    u16 cpu;
    u16 qdcount;
    u16 ancount;
    u16 len;
    u8  payload[DNS_PAYLOAD_MAX];
} dns_capture_t;

typedef struct dns_event {
    u16 qtype;                    // record TYPE (A=1, AAAA=28)
    u16 name_len;                 // owner name length
    u16 txid;                     // DNS transaction ID
    u16 answer_idx;               // 0-based index of this answer in the response
    u8  is_ipv6;                  // 0 = ip4 valid, 1 = ip6 valid
    u8  _pad[3];
    u32 ip4;                      // network byte order, valid if !is_ipv6
    u8  ip6[16];                  // valid if is_ipv6
    u32 ttl;                      // record TTL in seconds
    char  name[DNS_MAX_NAME_LEN + 1];  /* answer owner FQDN */
} dns_event_t;

// Per-CPU staging buffer: walk_answer appends each A/AAAA event here, then the
// emit program drains events[0 .. n) into the events ring buffer in one pass.
#define DNS_MAX_PENDING_EVENTS  16   // max answers buffered per packet

typedef struct dns_event_batch {
    u32 n;                                       // number of buffered events
    dns_event_t events[DNS_MAX_PENDING_EVENTS];
} dns_event_batch_t;


typedef enum dns_parser_error_e {
    DNS_PARSE_SUCCESS = 0,
    DNS_PARSE_ERR_NO_STATE,
    DNS_PARSE_ERR_INVALID_OFFSET,
    DNS_PARSE_ERR_OUT_OF_BOUNDS,
    DNS_PARSE_ERR_INVALID_LABEL_LEN,
    DNS_PARSE_ERR_INVALID_LITERAL_BITS,
    DNS_PARSE_ERR_LABEL_LEN,
    DNS_PARSE_ERR_LABEL_TOO_LONG,
    DNS_PARSE_ERR_NAME_BUF_OVERFLOW,
    DNS_PARSE_ERR_LABEL_PTR,
    DNS_PARSE_ERR_NAME_LEN,
    DNS_PARSE_ERR_DEPTH,
    DNS_PARSE_ERR_QUESTION_COUNT,
    DNS_PARSE_ERR_ANSWER_COUNT,
    DNS_PARSE_ERR_MAX_DEPTH,
} dns_parser_error_e;


#endif /* __DNS_PARSER_H */
