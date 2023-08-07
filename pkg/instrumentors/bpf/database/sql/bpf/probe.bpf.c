#include "arguments.h"
#include "span_context.h"
#include "go_context.h"
#include "go_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_QUERY_SIZE 100
#define MAX_CONCURRENT 50

struct sql_request_t {
    u64 start_time;
    u64 end_time;
    char query[MAX_QUERY_SIZE];
    struct span_context sc;
    struct span_context psc;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, void*);
	__type(value, struct sql_request_t);
	__uint(max_entries, MAX_CONCURRENT);
} context_to_sql_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 /* 256 KB */);
} events SEC(".maps");

// Injected in init
volatile const bool should_include_db_statement;
u64 ring_counter = 0;

// This instrumentation attaches uprobe to the following function:
// func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any)
SEC("uprobe/queryDC")
int uprobe_queryDC(struct pt_regs *ctx) {
    // argument positions
    u64 context_ptr_pos = 3;
    u64 query_str_ptr_pos = 8;
    u64 query_str_len_pos = 9;

    struct sql_request_t sql_request = {0};
    sql_request.start_time = bpf_ktime_get_ns();

    if (should_include_db_statement) {
        // Read Query string
        void *query_str_ptr = get_argument(ctx, query_str_ptr_pos);
        u64 query_str_len = (u64)get_argument(ctx, query_str_len_pos);
        u64 query_size = MAX_QUERY_SIZE < query_str_len ? MAX_QUERY_SIZE : query_str_len;
        bpf_probe_read(sql_request.query, query_size, query_str_ptr);
    }

    // Get goroutine as the key fro the SQL request context
    void *goroutine = get_goroutine_address(ctx, context_ptr_pos);

    // Get parent if exists
    struct span_context *span_ctx = bpf_map_lookup_elem(&spans_in_progress, &goroutine);
    if (span_ctx != NULL) {
        // Set the parent context
        bpf_probe_read(&sql_request.psc, sizeof(sql_request.psc), span_ctx);
        copy_byte_arrays(sql_request.psc.TraceID, sql_request.sc.TraceID, TRACE_ID_SIZE);
        generate_random_bytes(sql_request.sc.SpanID, SPAN_ID_SIZE);
    } else {
        sql_request.sc = generate_span_context();
    }

    bpf_map_update_elem(&context_to_sql_events, &goroutine, &sql_request, 0);
    // TODO : is this realy necessery if this is a leaf
    bpf_map_update_elem(&spans_in_progress, &goroutine, &sql_request.sc, 0);
    return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (db *DB) queryDC(ctx, txctx context.Context, dc *driverConn, releaseConn func(error), query string, args []any)
SEC("uprobe/queryDC")
int uprobe_queryDC_Returns(struct pt_regs *ctx) {
    u64 context_ptr_pos = 3;
    void *goroutine = get_goroutine_address(ctx, context_ptr_pos);
    struct sql_request_t *sqlReq_map_ptr = (struct sql_request_t *)bpf_map_lookup_elem(&context_to_sql_events, &goroutine);
    if (!sqlReq_map_ptr) {
        return 0;
    }

    struct sql_request_t *sqlReq_ring_ptr;
    sqlReq_ring_ptr = bpf_ringbuf_reserve(&events, sizeof(*sqlReq_ring_ptr), 0);
	if (!sqlReq_ring_ptr) {
        return 0;
    }


 	*sqlReq_ring_ptr = *sqlReq_map_ptr;
    sqlReq_ring_ptr->end_time = bpf_ktime_get_ns();

    ring_counter++;
    u64 flags = (ring_counter % 20 == 0) ? BPF_RB_FORCE_WAKEUP : BPF_RB_NO_WAKEUP;
    bpf_ringbuf_submit(sqlReq_ring_ptr, flags);

    bpf_map_delete_elem(&context_to_sql_events, &goroutine);
    bpf_map_delete_elem(&spans_in_progress, &goroutine);
    return 0;
}