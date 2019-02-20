#!/usr/bin/python
#
# test_xdsp.py 2 Test XDP path on the storage stack
#
# Copyright (c) 2019 Javier Gonzalez
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
import time
import sys

# global
device = ""

xdsp_flags = 0
xdsp_counter = 0

bpf_mode = 0
bpf_ret = ""
bpf_ctxtype = ""


def usage():
    print("Usage: {0} [-S] <blkdev>".format(sys.argv[0]))
    print("e.g.: {0} /dev/nvm0n1".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

device = sys.argv[1]

bpf_mode = BPF.XDSP
max_allowed = 256       # 4KB sectors (1MB)
ret_drop = "XDP_DROP" #TODO: CHANGE TO XDSP opcodes
ret_pass = "XDP_PASS" #TODO: CHANGE TO XDSP opcodes
bpf_ctxtype = "xdp_md"

# load BPF program
b = BPF(text = """
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>

BPF_TABLE("array", uint32_t, long, counter_table, 1);

int xdsp_prog1(struct CTXTYPE *ctx) {
    void* data_end = (void*)(long)ctx->data_end;
    void* data = (void*)(long)ctx->data;
    struct bio *bio = data;
    unsigned int sectors;
    uint32_t index = 0;
    long *cnt;

    sectors = bio->bi_iter.bi_size / 4096;

    cnt = counter_table.lookup(&index);
    if (cnt) {
        if (*(cnt) >= MAX)
            return RET_DROP;

        *cnt += sectors;
    }

    return RET_PASS;
}
""", cflags=["-w", "-DMAX=%d" % max_allowed, "-DRET_DROP=%s" % ret_drop, "-DRET_PASS=%s" % ret_pass, "-DCTXTYPE=%s" % bpf_ctxtype])

fn = b.load_func("xdsp_prog1", bpf_mode)

b.attach_xdsp(device, fn, xdsp_flags)

xdsp_counter = b.get_table("counter_table")

while 1:
    try:
        time.sleep(2)
        for k in xdsp_counter.keys():
            print("key {}".format(k.value))
            cnt = xdsp_counter.__getitem__(k).value
            print("Number of I/Os in dev {}".format(cnt))

    except KeyboardInterrupt:
        print("Detaching XDSP")
        break

#b.remove_xdsp(device, xdsp_flags)
