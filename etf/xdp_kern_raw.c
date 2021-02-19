#define KBUILD_MODNAME "blub"

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>

#include "etf.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") xsks_map = {
    .type        = BPF_MAP_TYPE_XSKMAP,
    .key_size    = sizeof(int),
    .value_size  = sizeof(int),
    .max_entries = 64,
};

SEC("xdp_sock")
int xdp_sock_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    int idx = ctx->rx_queue_index;
    unsigned long long nh_off;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return XDP_PASS;

    if (eth->h_proto != __builtin_bswap16(ETH_P_ETF))
        return XDP_PASS;

    /* If socket bound to rx_queue than redirect to user space */
    if (bpf_map_lookup_elem(&xsks_map, &idx))
        return bpf_redirect_map(&xsks_map, idx, 0);

    /* Else pass to Linux' network stack */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
