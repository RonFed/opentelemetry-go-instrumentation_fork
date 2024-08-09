// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "arguments.h"
#include "trace/span_context.h"
#include "go_context.h"
#include "go_types.h"
#include "uprobe.h"
#include "trace/start_span.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_CONCURRENT 50

bool wrote_to_flag = false;

// This instrumentation attaches uprobe to the following function:
// func probedFunction(f *bool)
SEC("uprobe/probedFunction")
int uprobe_probedFunction(struct pt_regs *ctx) {
    if (wrote_to_flag) {
        bpf_printk("Already wrote to flag");
        return 0;
    }
    void *f = get_argument(ctx, 1);
    if (f == NULL) {
        bpf_printk("f is NULL");
        return 0;
    }
    bool trueValue = true;
    long res = bpf_probe_write_user(f, &trueValue, sizeof(bool));
    if (res != 0) {
        bpf_printk("bpf_probe_write_user failed: %ld", res);
    }
    wrote_to_flag = true;
    bpf_printk("Wrote to flag");
    return 0;
}

