#!/usr/bin/env python
#
# Based on https://github.com/iovisor/bcc/blob/master/examples/tracing/nodejs_http_server.py
#

from __future__ import print_function
from bcc import BPF, USDT
import sys

if len(sys.argv) < 2:
    print("USAGE: trace.py [<pid>]+")
    exit()

bpf_text = """

#include <uapi/linux/ptrace.h>

int do_trace_start(struct pt_regs *ctx) {
    int i;
    bpf_usdt_readarg(1, ctx, &i);
    bpf_trace_printk("i=%d\\n", i);
    return 0;
};

int do_trace_end(struct pt_regs *ctx) {
    int i;
    bpf_usdt_readarg(1, ctx, &i);
    bpf_trace_printk("i=%d\\n", i);
    return 0;
};

TRACEPOINT_PROBE(sched, sched_switch) {
    bpf_trace_printk("next=%s\\n", args->next_comm);
    return 0;
};

TRACEPOINT_PROBE(sched, sched_wakeup) {
    bpf_trace_printk("comm=%s\\n", args->comm);
    return 0;
};

"""

u = USDT(pid=int(sys.argv[1]))
u.enable_probe(probe="cyclic_tp_start_work", fn_name="do_trace_start")
u.enable_probe(probe="cyclic_tp_end_work", fn_name="do_trace_end")

b = BPF(text=bpf_text, usdt_contexts=[u])

print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "ARGS"))

while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        print("value error")
        continue
    print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
